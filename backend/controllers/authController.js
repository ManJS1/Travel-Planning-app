// import express from 'express'
import User from '../models/User.js'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'


export const register = async(req,res)=>{
    try {
        const { username, email, password } = req.body;
    
        // Hash the password before saving to the database
        const hashedPassword = bcrypt.hashSync(password, 10);
    
        const newUser = await User.create({
          username: username,
          email: email,
          password: hashedPassword,
        });
    
        res.status(201).json({
          success: true,
          message: 'User registered successfully',
        });
      } catch (err) {
        // console.error('Error:', err);
        res.status(500).json({
          success: false,
          message: 'Failed to register user. Please try again.',
          error: err,
        });
    }
}


export const login = async(req,res)=>{

    const email = req.body.email;

    try {
        const user = await User.findOne({email});
        if(!user){
            return  res.status(404).json({
                success : false,
                message : "User not found"
            });
        };

        // const checkCorrectPassword = bcrypt.compare(req.body.password, user.password)

        const checkCorrectPassword = await bcrypt.compare(req.body.password ,user.password );

        if(!checkCorrectPassword){
            return res.status(401).json({
                success:false,
                message : "Invalid credentials"
            })
        }

        const {password , role , ...rest} = user._doc

        const token = jwt.sign({id : user._id, role : user.role},process.env.JWT_SECRET_KEY,{expiresIn : "15d"});

        res.cookie('accessToken',token,{
            httpOnly : true,
            expires : token.expiresIn
        }).status(200).json({
            success: true,
            token,
            data:{...rest},
            role
        })

    } catch (err) {
        console.error('Error:', err)
        res.status(500).json({
            success:false,
            message : "Failed to login. Try again"
        })
    }
}