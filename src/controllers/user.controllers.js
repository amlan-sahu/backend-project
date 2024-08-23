import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import {User} from "../models/users.models.js"
import {uploadOnCloudinary} from "../utils/cloudinary.js" 
import { ApiResponse } from "../utils/ApiResponse.js";



const generateAccessAndRefreshToken = async (userId) =>{
    try{
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({validateBeforeSave: false})

        return {accessToken, refreshToken}

    }catch(error){
        throw new ApiError(500, "Something went wrong while generating refresh and acess token")
    }
}



const registerUser = asyncHandler(async (req, res) => {
    // get user detail from frontend
    //validation - not empty
    //check if user already exists: username , email
    //check for images , check for avatar
    //upload them to cloudinary
    //crate user object - create entry in db
    //remove password and refresh token field from response
    //check user creation
    //retun response 


    const {fullName, email, username, password} = req.body
   // console.log("email:", email);

    if(
        [fullName, email, username, password].some((field) => field?.trim() === "")
    ){
        throw new ApiError("All fields are required", 400 )
    }

    const existedUser = await User.findOne({
        $or: [ { email},  { username}]
    })


    if(existedUser){
        throw new ApiError(409,"User with email or username already exists")
    }

   // console.log("req.files", req.files)

    const avatarLocalPath = req.files?.avatar[0]?.path;
   // const coverImageLocalPath = req.files?.coverImage[0]?.path;

   let coverImageLocalPath;

   if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
    coverImageLocalPath = req.files.coverImage[0].path
   }



    if(!avatarLocalPath){
        throw new ApiError("Avatar is required", 400)
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    

    if(!avatar){
        throw new ApiError("Avatar is required", 400)
    }

    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        username: username.toLowerCase(),
        password
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if(!createdUser){
        throw new ApiError(500, "Something went wrong while registering user")
    }

    return res.status(201).json(
        new ApiResponse(
            200, createdUser, "User created successfully")
    )
})

const loginUser = asyncHandler(async (req, res) => {
    // req body -> data
    // username or email
    //find the user 
    //password check
    //acess and refresh token
    //send cookie

    const {email,username,password } = req.body

    if(!email && !username){
        throw new ApiError("Email or username is required", 400)
    }

    const user = await User.findOne({
        $or: [{email}, {username}]
    })

    if(!user){
        throw new ApiError("User not found", 404)
    }

    const isPasswordValid = await user.isPsswoordCorrect(password)

    if(!isPasswordValid){
        throw new ApiError(401, "Invalid user credentials")
    }

    const {accessToken, refreshToken} = await generateAccessAndRefreshToken(user._id)

    const loggedInUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    const opation = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken", accessToken, opation)
    .cookie("refreshToken", refreshToken, opation).json(
        new ApiResponse(200, {
            user: loggedInUser,
            accessToken,
            refreshToken
        }, "User logged in successfully")
    )
})

const logoutUser =asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        },
    )

    const opation = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken", opation)
    .clearCookie("refreshToken", opation)
    .json( new ApiResponse(200, {}, "User logged out successfully"))

})


export { 
    registerUser,
    loginUser,
    logoutUser

}