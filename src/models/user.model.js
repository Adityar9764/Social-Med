import mongoose, {Schema} from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const userSchema = new Schema({
    username : {
        type : String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        index: true
    },
    email: {
        type : String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
    },
    fullName: {
        type : String,
        required: true,
        trim: true,
        index: true
    },
    avatar: {
        type: String,
        required: true,
    },
    coverImage: {
        type: String,
    },
    watchHistory: [{
        type: Schema.Types.ObjectId,
        ref: "Video"
    }],
    password: {
        type: String,
        required: [true, 'Password is required']
    },
    refreshToken: {
        type: String
    },
}, {timestamps: true})

// used for password encryption using bcrypt library
userSchema.pre("save", async function (next) {

    // this if statement is used to ensure that password is saved or reloaded in the database only when changes to it are made and not due to changes made in any other field like username, title etc
    if (!this.isModified("password")) { 
        return next()
    }
    this.password = await bcrypt.hash(this.password, 10)
    next() // next function is a part of every middleware as it sends the commmand that this middleware checking is done and you can move to the next one 
})

// to check if entered password is correct or not
userSchema.methods.isPasswordCorrect = async function (password) {
    return await bcrypt.compare(password, this.password)
}

// generating token by adding a method using the "methods", jwtwebtoken package is used in token generation
userSchema.methods.generateAccessToken = function () {
    jwt.sign({
        _id: this.id,
        email: this.email,
        username: this.username,
        fullName: this.fullName
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
        expiresIn: process.env.ACCESS_TOKEN_EXPIRY
    }
 )
}

userSchema.methods.generateRefreshToken = function () {
    jwt.sign({
        _id: this.id
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
        expiresIn: process.env.REFRESH_TOKEN_EXPIRY
    }
 )
}

export const User = mongoose.model("User", userSchema)