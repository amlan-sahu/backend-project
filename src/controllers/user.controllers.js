import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import {User} from "../models/users.models.js"
import {uploadOnCloudinary} from "../utils/cloudinary.js" 
import { ApiResponse } from "../utils/ApiResponse.js";


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
    console.log("email:", email);

    if(
        [fullName, email, username, password].some((field) => field?.trim() === "")
    ){
        throw new ApiError(
            "All fields are required",
            400
        )
    }

    const existedUser = User.findOne({
        $or: [ { email},  { username}]
    })


    if(existedUser){
        throw new ApiError(409,"User with email or username already exists")
    }

    const avatarLocalPath = req.files?.avatar[0]?.path;
    const coverImageLocalPath = req.files?.coverImage[0]?.path;

    if(!avatarLocalPath){
        throw new ApiError("Avatar is required", 400)
    }

    const avatar = await uploadOnCloadinary(avatarLocalPath);
    const coverImage = await uploadOnCloadinary(coverImageLocalPath);

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


export { registerUser }