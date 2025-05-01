import Mailgen from "mailgen"
import nodemailer from 'nodemailer'

const sendMail = async(options) => {
    const mailGenerator = new Mailgen({
        theme: 'default',
        product: {
            name: 'IPO Connect',
            link: 'https://mailgen.js/',
        }
    });

    var emailBody = mailGenerator.generate(options.mailGenContent);
    var emailText = mailGenerator.generatePlaintext(options.mailGenContent);

    const transporter = nodemailer.createTransport({
        host: process.env.MAILTRAP_HOST,
        port: process.env.MAILTRAP_PORT,
        secure: false, // true for port 465, false for other ports
        auth: {
          user: process.env.MAILTRAP_USERNAME,
          pass: process.env.MAILTRAP_PASSWORD,
        },
    });

    const mail ={
        from: 'ipoconnect@example.com', // sender address
        to: options.email, // list of receivers
        subject: options.subject, // Subject line
        text: emailText, // plain text body
        html: emailBody, // html body
    };

    try {
        await transporter.sendMail(mail)
    } catch (error) {
        console.error("Email failed", error);
    }
}

const emailVerificationMailGenContent = (username, verificationUrl) => {
    return {
        body: {
            name: username,
            intro: 'Welcome to IPOConnect website! We\'re very excited to have you on board.',
            action: {
                instructions: 'To get started with our website, please click here:',
                button: {
                    color: '#22BC66', // Optional action button color
                    text: 'Verify your email',
                    link: verificationUrl
                }
            },
            outro: 'Need help, or have questions? Just reply to this email, we\'d love to help.'
        }
    }
}

const forgotPasswordMailGenContent = (username, passwordResetUrl) => {
    return {
        body: {
            name: username,
            intro: 'We got a request to reset your password',
            action: {
                instructions: 'To change your password click the button',
                button: {
                    color: '#22BC66', // Optional action button color
                    text: 'Reset password',
                    link: passwordResetUrl
                }
            },
            outro: 'Need help, or have questions? Just reply to this email, we\'d love to help.'
        }
    }
}

export {sendMail, emailVerificationMailGenContent, forgotPasswordMailGenContent}