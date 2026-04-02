var wasm_instance = null;
export default async function init(wasm_file){
    try{
        wasm_instance = await WebAssembly.instantiateStreaming(fetch(wasm_file));
    }catch(err){
        console.error("Wasm failed to load:", err);
    }
    console.log(wasm_instance.instance.exports);
    return wasm_instance.instance.exports;
}

export const get_bytecode_ptr = ()=>{
    return wasm_instance.instance.exports.get_bytecode_ptr();
}

export const get_mem_ptr = ()=>{
    return wasm_instance.instance.exports.get_mem_ptr();
}

export const run_vm = ()=>{
    return wasm_instance.instance.exports.run_vm();
}
