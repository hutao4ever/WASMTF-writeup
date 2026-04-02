 //this is not part of the challenge
 import { serveDir } from "jsr:@std/http/file-server";

 Deno.serve({ port: 8000 }, (req) => {
     return serveDir(req, {
         fsRoot: ".",
         showDirListing: true,
         enableCors: true,
     });
 });

 console.log("Serving current directory at http://localhost:8000");
