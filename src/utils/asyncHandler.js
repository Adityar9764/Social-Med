const asyncHandler = (requestHandler) => {
    return (req, res, next) => {
        Promise.resolve(requestHandler(req, res, next))
        .catch((err) => next(err))
    }
}


export {asyncHandler}

/*
another way of doing this is using async await and trycatch

const asyncHandler = (func) => async (req, res, next) => {
    try{
    await func(req, res, next)
    } catch (error) {
    res.status(err.code || 500.json ({
        success: false,
        message: err.message
    })
    }
}
*/

/* 
const asyncHandler = (func) => async () => {}  is explained down

const asyncHandler = () => {} 
const asyncHandler = (func) => {  () => {}  }
const asyncHandler = (func) => async {    () => {}    }
const asyncHandler = (func) => async () => {}
*/

