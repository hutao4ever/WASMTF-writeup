# WASMTF - Alberta CTF 2026 Challenge Writeup

WASMTF is a web assembly reverse engineering challenge. We are presented with a website where we can put in a key and it will give us some output. If we enter the right one, we hopefully will get the flag.

![wasmtf challenge site](https://github.com/hutao4ever/WASMTF-writeup/blob/main/website.png?raw=true)

To run the challenge yourself, download the repository and use Deno to run serve.js
Run command:`deno run serve.js`

# First look

If we open up the devtools, we can see that the site is loading a web assembly program `wasmtf_bg.wasm`. There is a JS block embedded in the HTML. It puts a bytecode, an encrypted flag and our key into web assembly memory. Then, it executes the `run_vm` function from the wasm program. Finally, it displays the decrypted flag, which is also read from web assembly memory.

```
<script  defer="defer"  type="module">

import init, { get_bytecode_ptr, run_vm, get_mem_ptr } from  "./wasmtf.js";

function hexToUint8Array(hexString) {
	if (hexString.length % 2  !==  0) {
		throw new Error("Invalid hex string: length must be even.");
	}

	const view = new Uint8Array(hexString.length / 2);

	for (let i = 0; i < hexString.length; i += 2) {
		view[i / 2] = parseInt(hexString.substring(i, i + 2), 16);
	}
	
	return view;
}

init("./wasmtf_bg.wasm").then(wasm  => {
	function get_memory() {
		return new Uint8Array(wasm.memory.buffer);
	}

	const bytecode = hexToUint8Array("1ae0004be04016e1cc11e1cc16e1cc60e1cc5003cc40e0cc51f9cc19e3e018e3cc1ae2004be24016e3cc11e3cc16e0cc40e3cc11e3cc16e1cc18e2cc1ae2004be20016e3cc11e3cc16e3cca0e1e316e3cc42e0e319e0e116e1cc40e2cc1ae30463e2e35002cc51f3cc14e1cc14e0cc16e2cc4be20216e2cc16e3cc63e2e35003cc18e3cc51e0ccffcccc");
	const encrypted_flag = hexToUint8Array("16460251085e4f113f7841514a4e051551122e782c5c7c104a125d0141156d22");

	const memory = get_memory();
	const bytecode_ptr = get_bytecode_ptr();
	const mem_ptr = get_mem_ptr();

	memory.set(bytecode, bytecode_ptr);
	memory.set(encrypted_flag, mem_ptr + 64);

	const $button = document.getElementById("check-button");
	
	if ($button === null) {
		alert("challenge broken :/");
		return;
	}

	$button.addEventListener("click", () => {
		event.preventDefault();
		const  $input = document.getElementById("flag-input");
		
		if ($input === null) {
			alert("challenge broken :/");
			return;
		}

		const  encoder = new TextEncoder();
		const  before = get_memory();
		const  encoded_user_input = encoder.encode($input.value).subarray(0, 63)

		before.set(encoded_user_input, mem_ptr);

		run_vm();

		const after = get_memory();
		const decrypted_flag = after.subarray(mem_ptr + 128, mem_ptr + 128 + 64);
		
		document.getElementById("display-flag").hidden = false;
		document.getElementById("decrypted-flag").innerText = new TextDecoder().decode(decrypted_flag);
	});
});

</script>
```
We can already guess from the presence of bytecode that this challenge involves a virtual machine(VM). Which is basically a program that translates a custom bytecode into actual executable code, in this case, web assembly. This translation layer makes it harder for us to know the real logic.
However, the VM is not present in the JS code. We can't make any sense of the bytecode and the encrypted flag without decoding the web assembly program.

## Reverse Engineering run_vm

We will be using Ghidra to analyze `wasmtf_bg.wasm`. Because Ghidra doesn't come with web assembly support, we have to install this [plugin](https://github.com/nneonneo/ghidra-wasm-plugin). 
After the plugin is set up, we can just import the file and start analyzing.

From Ghidra's symbol tree, we see the wasm program exports 3 functions:
`get_bytecode_ptr`
`get_mem_ptr`
`run_vm`

The first 2 are simple functions that return a memory address, telling JS code where to put the bytecode and the encrypted flag. The run vm function contains actual logic.

The decompiled output looks like this:
![ghidra screenshot](https://github.com/hutao4ever/WASMTF-writeup/blob/main/ghidra1.png?raw=true)

The most obvious part is the `local_414` array, which maps a bunch of numbers to other numbers. In the context of a VM, this is a dispatch table, where custom bytecode is mapped to a handler function that executes the corresponding logic. Basically, each function is given an alias. This alias is usually called an **opcode**.

`local_14` is an array that stores 3 pointers and VM states.
`local_14[0]`--mem_ptr, which is the pointer returned by `get_mem_ptr`
`local_14[1]`--pointer to unknown memory, likely the stack used by the VM
`local_14[2]`--bytecode_ptr, which is the pointer returned by `get_bytecode_ptr`
`local_8` is technically also part of this array, because it comes right after in memory(if you read the offsets in the wasm instructions).
We will refer to the array as **vm_data** from now on.

The while loop is a typical fetch-decode-execute cycle in VMs. It iterates through the given bytecode, executing it one by one. Ghidra made a mess here. But the first line in the loop is just using the dispatch table to execute the corresponding function of the bytecode. 
Note this part: `local_414[uVar2] * 4`
The number gotten from the table is multiplied by 4 to get the final address of the handler function.
`uVar3` is the current opcode and `bVar3` is the **program counter(PC)**, which is the index of the current bytecode instruction to be executed.
We also notice that the handler function is called with 2 parameters(operands): `(int)&DAT_ram_00100398 + (uint)(byte)(bVar3 + 1)` and `(int)&DAT_ram_00100398 + (uint)(byte)(bVar3+2)`. Now we know each bytecode instruction is 3 bytes, the first being the opcode and 2 operands follow.

The rest of the loop is just incrementing the PC by 3 every iteration. (Because instructions are 3 bytes long) 
From this `bVar3 = local_8._6_1_ + 3`, we know the PC is also stored in the 7th byte of `local_8`or `vm_data+18` in addition to bVar3.
This line is also quite interesting: `if ((uVar2 & 0xfe) != 0x50) {`
When the opcode is 0x50 or 0x51, the condition is false and we don't increment the PC. This implies that these opcodes represents jump instructions.

After renaming some variables:
![ghidra screenshot](https://github.com/hutao4ever/WASMTF-writeup/blob/main/ghidra2.png?raw=true)

## Reverse Engineering all the handler functions

From `run_vm`, we saw how the final address of the handler functions are determined.
If you look at the wasm instructions for that line, you see handler functions are actually called by this line: `call_indirect type=0x1 table0`. `table 0` is where all the handlers are located. In Ghidra, you can go to any handler function by pressing g and typing in this expression:
`table0+(number from the dispatch table)*4`

You can either manually find out what each function does(they are pretty simple), or just copy everything into your favorite clanker and let it tell you. 

This is a table of all handler functions:

| Opcode | Mnemonic | Description | Format |
|--------|----------|-------------|--------|
| `0x11` | `PUSH_IND reg` | Push `js_memory[reg]` onto stack | `11 reg XX` |
| `0x14` | `STORE_OUT reg` | Write reg to `js_memory[write_idx++]` | `14 reg XX` |
| `0x16` | `POP reg` | Pop stack into register | `16 reg XX` |
| `0x18` | `PUSH reg` | Push register onto stack | `18 reg XX` |
| `0x19` | `MOV dst, src` | Copy src register to dst register | `19 dst src` |
| `0x1A` | `LDI reg, imm8` | Load value into register | `1A reg imm` |
| `0x40` | `INC reg` | Increment register by 1 | `40 reg XX` |
| `0x42` | `XOR reg1, reg2` | Push `reg1 ^ reg2` onto stack | `42 r1 r2` |
| `0x4B` | `PUSH_ADD reg, imm8` | Push `reg + imm8` onto stack | `4B reg imm` |
| `0x4D` | `PUSH_SUB reg, imm8` | Push `reg - imm8` onto the stack | `4D reg imm` |
| `0x50` | `BRZ operand1` | Branch(jump) if zero flag: `PC += op1*3` | `50 off XX` |
| `0x51` | `JMP offset` | Branch(jump) to an offset (relative to current PC) | `51 imm XX` |
| `0x60` | `TST_Z reg` | Set flag if `reg == 0` | `60 reg XX` |
| `0x63` | `CMP_LE reg1, reg2` | Set flag if `reg2 <= reg1` | `63 r1 r2` |
| `0xA0` | `SCRAMBLE reg1, reg2` | Does this `(r2<<5) ^ ((r2<<2)\|(r1>>4)) ^ r1` and push result onto stack| `A0 r1 r2`|
| `0xFF` | `HALT` | Stop execution | `FF` |

As an example, this is the renamed handler for `0x18`:
![ghidra screenshot](https://github.com/hutao4ever/WASMTF-writeup/blob/main/ghidra3.png?raw=true)
We can see the last line adding an offset/index to the unknown pointer at `vm_data + 4` (remember `local_14[1]` in `run_vm`?)  and writing the value of the register there.

`vm_data + 0x10` is the index used to access the pointed memory. It decrements it by 1 and updates the original value. Finally, the value of the selected register is written to that index.

This proves the unknown memory is a stack. The index decrements every push, so a new value is written right before the last value on the stack. We can see the opposite happening in function `0x16`, which pops the stack.

After looking at all the functions, we find out what states are stored in vm_data.
This is the layout of vm_data array in memory:
`9c 05 10 00` <--mem_ptr
`9c 04 10 00` <--stack base pointer
`98 03 10 00` <--bytecode_ptr
`00 00 00 00` <--registers: e0 e1 e2 e3
`ff 80 00 00` <--SP(stack pointer), JS memory index, PC, zero flag (the flag mentioned in the table above)

## Analyzing the bytecode
Knowing how the VM works is only half the challenge. Now, we have enough info to analyze the bytecode fed into the VM.

This is what we saw in JS code.
`const bytecode = hexToUint8Array("1ae0004be04016e1cc11e1cc16e1cc60e1cc5003cc40e0cc51f9cc19e3e018e3cc1ae2004be24016e3cc11e3cc16e0cc40e3cc11e3cc16e1cc18e2cc1ae2004be20016e3cc11e3cc16e3cca0e1e316e3cc42e0e319e0e116e1cc40e2cc1ae30463e2e35002cc51f3cc14e1cc14e0cc16e2cc4be20216e2cc16e3cc63e2e35003cc18e3cc51e0ccffcccc");`

We must split this string into segments of 3 bytes, because we know each instruction is 3 bytes long.
We know the first byte is the opcode and 2 operand bytes follow. So just look up the opcode of each instruction in the table above and we can easily see what the bytecode does.

The full commented bytecode is shown below:
```
1a e0 00 write 0 to the e0 register
4b e0 40 push the value of register e0 + 0x40 to stack
16 e1 cc pop the stack and store to e1 register
11 e1 cc use the value register e1 as an offset for js memory and push the read byte to stack
16 e1 cc pop the stack and store to e1 register
60 e1 cc test if e1 register is 0, set zero flag
50 03 cc if 0 flag is set, jump 3 instructions ahead
40 e0 cc increment value of e0 register by 1
51 f9 cc jump 7 intructions back
^--finds the length of the encrypted flag
19 e3 e0 copy the value of e0 register to e3 register
18 e3 cc push the value of e3 register to stack
^--put length of flag on the stack
1a e2 00 write 0 to the e2 register
4b e2 40 push the value of register e2 + 0x40 to stack <--big loop start
16 e3 cc pop the stack and store to e3 register
11 e3 cc read e3 register, use its value as an offset for js memory and push the value to stack
16 e0 cc pop the stack and store to e0 register 
^--first byte of flag goes to e0
40 e3 cc increment value of e3 register by 1
11 e3 cc read e3 register, use its value as an offset for js memory and push the value to stack
16 e1 cc pop the stack and store to e1 register
^--second byte of flag goes to e1
18 e2 cc push the value of e2 register to stack
1a e2 00 write 0 to the e2 register
4b e2 00 push the value of register e2 + 0x00 to stack <--small loop start, e2 is the index
16 e3 cc pop the stack and store to e3 register
11 e3 cc read e3 register, use its value as an offset for js memory and push the value to stack
16 e3 cc pop the stack and store to e3 register
^--1 byte of user input goes to e3
a0 e1 e3 mix the value of e1 and e3 register and push the value to stack
16 e3 cc pop the stack and store to e3 register
42 e0 e3 xor the value of register e0 with e3 and push the value to stack
19 e0 e1 copy the value of e1 register to e0 register 
16 e1 cc pop the stack and store to e1 register <--final result in e1
40 e2 cc increment value of e2 register by 1
1a e3 04 write 4 to the e3 register
63 e2 e3 test if e3 <= e2 , set zero flag
50 02 cc if 0 flag is set, jump 2 instructions ahead <--break small loop
51 f3 cc jump 13 instructions back
14 e1 cc write the value of register e1 into js memory
14 e0 cc write the value of register e0 into js memory
16 e2 cc pop the stack and store to e2 register
4b e2 02 push the value of register e2 + 0x02 to stack
16 e2 cc pop the stack and store to e2 register
16 e3 cc pop the stack and store to e3 register
63 e2 e3 test if e3 <= e2, set zero flag
50 03 cc if 0 flag is set, jump 3 instructions ahead <--break big loop
18 e3 cc push the value of e3 register to stack
51 e0 cc jump 32 instructions back
ff cc cc end program
```
Although the bytecode seems to be massive, most of it is just moving values between registers and the stack. 

The important logic starts at the **small loop**. It is hardcoded to loop 4 times, so only the first 4 bytes of the key input is actually used. 

It takes 2 bytes from the encrypted flag and executes an elaborate mix operation with the key implemented by function `0xa0` (please look at it yourself). 
The mix operation is here:
> result = (reg2 <<  5)  ^  ((reg2 <<  2)  |  (reg1 >>  4))  ^ reg1

The decryption process is rather hard to explain with words, so just look at the diagram and python implmentation of the algorithm. 

![algorithm diagram](https://github.com/hutao4ever/WASMTF-writeup/blob/main/algorithm.png?raw=true)

Full Python implementation in `algo.py`.

After the small loop is done, the big loop is simply going to write the decrypted result to memory readable by the JS code and fetch the next 2 bytes of the encrypted flag, repeating the same process. The algorithm processes the encrypted flag in independent groups of 2 bytes, so no mixing happens between groups.

## Solving the challenge

Finally, we reach the last step. This algorithm is super complex and I'm not smart enough to understand it. However, if we take a careful look at the diagram above, we notice the last byte of the key is only involved in outputting the 1st byte of the decrypted flag. The 2nd byte of the decrypted flag only depend on the first 3 bytes of the key. 

Also, we know the flag format is `abctf{...}`. So the 2nd byte of the correctly decrypted flag should be `b`.

This means we don't need to understand the algorithm. We can just try every combination of the first 3 bytes of the key and those that give us the right character is a potential correct key. 

We have to try `255*255*255=16581375` combinations in the worst case, which takes less than 10 seconds even in a slow language like Python. 

For every key that gives us `b`, we are going to try all 255 possible last byte of the key. If the final decrypted flag matches the format `abctf{...}`, we know we have found the flag.

The full python solution is in `solver.py`, so go check that out.
It should spit out something like this:
```
abctf{n0t_$p0n$0r3d_By_1h3m!d4}
[8, 155, 218, 119]
abctf{n0t_$p0n$0r3d_By_1h3m!d4}
[8, 155, 218, 183]
abctf{n0t_$p0n$0r3d_By_1h3m!d4}
[8, 155, 218, 247]
abctf{n0t_$p0n$0r3d_By_1h3m!d4}
[8, 178, 40, 23]
abctf{n0t_$t0j$4r3d_By_1h3m!d4}
[8, 178, 40, 87]
abctf{n0t_$t0j$4r3d_By_1h3m!d4}
```
Some of it is wrong due to quirks in the algorithm, but I'm sure we can read English words. ;)

## Conclusion
This is the only Alberta CTF challenge that can't be solved using the free tier of claude. Tuff shi, challenge author! 
Although the final solution is kind of gay, because an observant person can potentially brute force it without ever looking at the WASM program.

