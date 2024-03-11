// import multer from "multer";
// import { GridFsStorage } from "multer-gridfs-storage";

// import "dotenv/config";



// const storage = new GridFsStorage({
//   url: process.env.DB_LOCATION,
//   options: { useNewUrlParser: true },
//   file: (request, file) => {
//     const match = ["image/png", "image/jpg"];

//     if (match.indexOf(file.memeType) === -1)
//       return `${Date.now()}-blog-${file.originalname}`;

//     return {
//       bucketName: "photos",
//       filename: `${Date.now()}-blog-${file.originalname}`,
//     };
//   },
// });

// export default multer({ storage });


const upload = multer({
  dest: "uploads/",
  limits: { fileSize: 50 * 1024 * 1024 }, // 50 mb in size max limit
  storage: multer.diskStorage({
    destination: "uploads/",
    filename: (_req, file, cb) => {
      cb(null, file.originalname);
    },
  }),
  fileFilter: (_req, file, cb) => {
    let ext = path.extname(file.originalname);
    if (
      ext !== ".jpg" &&
      ext !== ".jpeg" &&
      ext !== ".webp" &&
      ext !== ".png" &&
      ext !== ".mp4"
    ) {
      cb(new Error(`Unsupported file type! ${ext}`), false);
      return;
    }

    cb(null, true);
  },
});