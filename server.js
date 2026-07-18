import app from "./src/app.js";
import connectDB from "./src/config/databse.js"


connectDB();

app.listen(3000,()=>{
    console.log("server is running on 3000 port")
})


