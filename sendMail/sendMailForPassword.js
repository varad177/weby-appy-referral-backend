import nodemailer from "nodemailer";


const sendEmailForPassword = async function (email, sub, resetUrl) {
  const transporter = nodemailer.createTransport({
    // host:process.env.SMPT_HOST,
    // port: process.env.SMPT_PORT,
    host: "smtp.elasticemail.com",
    port: 587,
    secure: false,
    auth: {
      user: process.env.MAIL_USER,
      // user:'april61@ethereal.email' ,
      // pass:process.env.SMPT_PASSWORD
      pass: process.env.MAILPASS,
    },
  });

 

  await transporter.sendMail({
    // from: process.env.SMPT_FROM_HOST ,
    from: "fakeacc6862@gmail.com",
    to: email,
    subject: sub,
    html: `
    
    <!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
        }

        .container {
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 20px;
            width: 300px;
            text-align: center;
        }

        h1 {
            color: #333;
        }

        p {
            color: #666;
        }

        .button {
            display: inline-block;
            padding: 10px 20px;
            font-size: 16px;
            text-align: center;
            text-decoration: none;
            background-color: #ff7300;
            color: #fff;
            border-radius: 4px;
            cursor: pointer;
        }

        .button:hover {
            background-color: rgb(251, 84, 7)
        }
    </style>
</head>

<body>
    <div class="container">
        <h1>Forgot Password</h1>
        <p>We received a request to reset your password. Click the button below to reset it:</p>
        <a class="button" href=${resetUrl}>Reset Password</a>
        <p>If you did not request a password reset, please ignore this email.</p>
    </div>
</body>

</html>

    `,
  });
};

export default sendEmailForPassword;
