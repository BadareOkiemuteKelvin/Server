const express = require("express")
const cors = require("cors");
const router = express.Router()
const app = express();

app.use(cors({"Access-Control-Expose-Headers": "Content-Range"}));


app.get("/app",(req,res)=>{
    res.send("Server is Live")
})


app.listen(8000,()=>{
    console.log("Server is live")
})