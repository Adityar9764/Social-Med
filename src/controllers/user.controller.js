import { asyncHandler } from "../utils/asyncHandler.js";
import {ApiError} from "../utils/APIError.js"
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import {ApiResponse} from "../utils/ApiResponse.js";
import { jwt } from "jsonwebtoken";
import mongoose from "mongoose";


const generateAccessAndRefreshTokens = async(userId) => {
    try {
       const USER = await User.findById(userId)
       const accessToken = USER.generateAccessToken()
       const refreshToken = USER.generateRefreshToken()

       USER.refreshToken = refreshToken
       await USER.save({validateBeforeSave: false})

       return {accessToken, refreshToken}

    } catch (error) {
        throw new ApiError(500, "Something went wrong during token generation")
    }
}


const registerUser = asyncHandler ( async (req,res) => {
    // get user details from frontend 
    // validation - not empty
    // check if user already exists: username, email
    // check for images, avatar is compulsory
    // upload them to cloudinary, avatar check,
    // create user object - create entry in db
    // remove password and refresh token field from response to user
    // check for user creation
    // return res

    const {fullName, email, username, password} = req.body
    if (
        [fullName, email, username, password].some((field) => field?.trim() === "")
    ) {
        throw new ApiError(400, "All Fields are required")
    }

    // checking if the user already exists
    const existedUser = await User.findOne({$or: [{username}, {email}] })
    if (existedUser) {
        throw new ApiError(409, "User with email or username already exists")
    }

    const avatarLocalpath = req.files?.avatar[0]?.path;    //  it attempts to retrieve the local file path of an uploaded file named "avatar" from the incoming HTTP request.
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;   //  it attempts to retrieve the local file path of an uploaded file named "coverImage" from the incoming HTTP request.
    // another way of writing the same thing 
    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage > 0) {
        coverImageLocalPath = req.files.coverImage[0].path
    }

    if (!avatarLocalpath) {
        throw new ApiError(400, "Avatar Image is required")
    }

    const avatar = await uploadOnCloudinary(avatarLocalpath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if (!avatar) {
        throw new ApiError(400, "Avatar file is required")
    }

    // finally creating a user after taking every input from the frontend and storing these details of the user in the DB(refer user.model.js)
    const usercreation = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",  // agar coverImage hai toh url store kardo uska DB me creation ke time, nai h toh woh jagah khali chod do 
        email,
        password,
        username: username.toLowerCase()
    })

    // mongoDB genreates a _id after every new entry, so we can verify if a new user is created or not by using findbyid method
    const createdUser = await User.findById(usercreation._id).select(
        "-password -refreshToken"
    )
    
    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registration")
    }

    // returning response
    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered successfully")
    )
})


const loginUser = asyncHandler( async (req,res) => {
    // req body -> data
    // username or email
    // find the user
    // password check
    // access and refresh tokens
    // send cookie and response

    const {email, username, password} = req.body

    if (! (username || email) ) {
        throw new ApiError(400, "username or email is required")
    }

    const user = await User.findOne({
        $or: [{username}, {email}]
    })
    
    if (!user) {
        throw new ApiError(404, "User does not exists")
    }

    const isPasswordValid = await user.isPasswordCorrect(password)

    if (!isPasswordValid) {
        throw new ApiError(401, "Invalid user Credentials")
    }

    const {accessToken, refreshToken} = await generateAccessAndRefreshTokens(user._id)

    const loggedInUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res.status(200)
    .cookie("accessToken",accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(
            200,
            {
                user: loggedInUser, accessToken, refreshToken
            },
            "User Logged In Successfully"
        )
    )
})


const logoutUser = asyncHandler( async(req,res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, "User Logged Out"))
})


const refreshAccessToken = asyncHandler( async(req,res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if (!incomingRefreshToken) {
        throw new ApiError(401, "Unauthorized request")
    }

    try {
    
    const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)  // a jwt token is a token which has multiple sections and upon decoding, it futher breakes down into header, payload and verify signature parts

    const user = await User.findById(decodedToken?._id)  // uss decode token ka use karke we will find out ki konsa user hai jiska session aur accessToken refresh karna h 

    if (!user) {
        throw new ApiError(401, "Invalid refresh Token")
    }

    // verifying if the incomingrefreshToken that is coming from the frontend is same as the refresh token that is stored in the Database corresponding to that particular user 
    if (incomingRefreshToken !== user?.refreshToken) {
        throw new ApiError(401, "Refresh Token is expired or used")
    }

    const options = {
        httpOnly: true,
        secure: true
    }

    const { accessToken, newrefreshToken } = await generateAccessAndRefreshTokens(user._id)  // generating new tokens corresponding to that particular user id 
    // accessToken to waise bhi expire ho gaya tha isliye naming me no issues par as we are rewriting/generating the refresh token toh name "newrefreshToken" is better


    return res.status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", newrefreshToken, options)
    .jsonn(
        new ApiResponse(200, {accessToken, refreshToken: newrefreshToken},
            "AccessToken refreshed"
        )
    )}
     catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token")
    }
})


const changeCurrentPassword = asyncHandler( async(req,res) => {
    const {oldPassword, newPassword} = req.body

    const user = await User.findById(req.user?._id)

    const ispasswordcorrect = await user.isPasswordCorrect(oldPassword)

    if (!ispasswordcorrect) {
        throw new ApiError(400, "Invalid old password")
    }

    user.password = newPassword
    await user.save({validateBeforeSave: false})

    return res.status(200).json(new ApiResponse(200, "Password changed successfully"))
})


const getCurrentUser = asyncHandler( async(req, res) => {
    return res.status(200)
    .json(new ApiResponse(200, req.user , "Current user fetched successfully"))
})


const updateAccountDetails = asyncHandler( async(req, res) => {
    const {fullName, email} = req.body

    if (!fullName || !email) {
        throw new ApiError(400, "All fields are required")
    }

    const user = await User.findByIdAndUpdate(req.user?._id,
        {
            $set: {
                fullName: fullName,
                email: email
            }
        },
        { new: true }
    ).select("-password")

    return res.status(200).json(new ApiResponse(200, "Account Details Updated Successfully"))
})


const updateUserAvatar = asyncHandler( async (req, res) => {

    const avatarLocalPath = req.file?.path

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is missing please select a file")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if (!avatar.url) {
        throw new ApiError(400, "Error while uploading")
    }

    const user = await User.findByIdAndUpdate(req.user?._id,
        {
            $set: {
                avatar: avatar.url
            }
        },
        {new: true}
    ).select("-password")

    return res.status(200).json(new ApiResponse(200, user, "Avatar Updated Successfully"))
})


const updateUserCoverImage = asyncHandler(async(req, res) => {
    const coverImageLocalPath = req.file?.path

    if (!coverImageLocalPath) {
        throw new ApiError(400, "Cover image file is missing")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if (!coverImage.url) {
        throw new ApiError(400, "Error while uploading on avatar")
        
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                coverImage: coverImage.url
            }
        },
        {new: true}
    ).select("-password")

    return res
    .status(200)
    .json(
        new ApiResponse(200, user, "Cover image updated successfully")
    )
})


const getUserChannelProfile = asyncHandler( async(req,res) => {
    
    const {username} = req.params

    if (!username?.trim()) {
        throw new ApiError(400, "Username is Missing")
    }

    const channel = await User.aggregate([
        {
            $match: {username: username?.toLowerCase()}
        },
        {
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "channel",
                as: "subscribers"
            }   // this pipeline uses lookup command and it gives/returns an array of all channels(Subscribers) which are associated (have subscribed to) with a user (again need to remember user is also a channel in itself like it happens in youtube)
        },
        {
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "subscriber",
                as: "subscribedTo"
            }   // this pipeline returns an arrray of all the users(channels again like in youtube) that a particular user has subscribed to
        },
        {
            $addFields: {
                subscribersCount: {
                    $size: "$subscribers"
                },   // gives the size (finalcount) of subscibers (user/channels) which have subscribed to a particular user

                channelsSubscribedToCount: {
                    $size: "$subscribedTo"
                },  // gives the size (finalcount) of the channels (users) which a the selected user has subscribed to

                isSubscribed: {
                    $cond: {
                        if: {$in: [req.user?._id, "$subscribers.subscriber"]},
                        then: true,
                        else: false
                    }
                }   // helps us know whether the user (who is currently logged in) has subscribed to the channel that he/she is currently viewing or not
            }
        },
        {
            $project: {
                fullName: 1,
                username: 1,
                subscribersCount: 1,
                channelsSubscribedToCount: 1,
                isSubscribed: 1,
                avatar: 1,
                coverImage: 1,
                email: 1
            }
        }
    ])

    if (!channel?.length) {
        throw new ApiError(404, "Channel Does Not Exists")
    }

    return res.status(200)
    .json(new ApiResponse(200, channel[0], "User Channel Details Fetched Successfully"))
})


const getWatchHistory = asyncHandler( async(req,res) => {

    const user = await User.aggregate([
        {
            $match: {_id: new mongoose.Types.ObjectId(req.user._id)}
        },
        {
            $lookup: {
                from: "videos",
                localField: "watchHistory",
                foreignField: "_id",
                as: "watchHistory",

                pipeline: [
                    {
                        $lookup: {
                            from: "users",
                            localField: "owner",
                            foreignField: "_id",
                            as: "owner",
                            pipeline: [{$project: {fullName:1,username:1,avatar:1}}]
                        }
                    },
                    {
                        $addFields: {owner: {$first: "$owner"}}
                    }
                ] 
            }
        } 
    ])

    return res.status(200)
    .json(
        new ApiResponse(200, user[0].getWatchHistory, "Watch History Fetched Successfylly")
    )

})


export { 
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage,
    getUserChannelProfile,
    getWatchHistory
}