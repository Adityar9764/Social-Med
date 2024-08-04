import { v2 as cloudinary} from "cloudinary";
import fs from "fs";

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SCERET
});


const uploadOnCloudinary = async (localFilePath) => {
    try {
        if (!localFilePath) {
            return null
        }
        // upload the file on cloudinary 
        const response = await cloudinary.uploader.upload(localFilePath, {
            resource_type: "auto"
        })
        console.log("File has been uploaded",response.url);
        // fs.unlinkSync(localFilePath) // after the file is uploaded on DB using cloudinary unlink the file 
        return response;

    } catch (error) {
        fs.unlinkSync(localFilePath)  // remove the locally save temporary instance file as the upload operation got failed
        return null
    }
}

export {uploadOnCloudinary}