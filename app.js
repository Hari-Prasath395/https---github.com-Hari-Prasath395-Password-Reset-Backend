require('dotenv').config();
const express = require('express');
const app = express();
const cors = require('cors');
const cookieParser = require('cookie-parser');
const router = require('./Routes/routes');
const port = 8000;

require('./dbconfig');





app.use(express.json());
app.use(cors());
app.use(cookieParser());
app.use(router);

app.listen(port, () => {
  console.log(`Server started at port: ${port}`);
});
