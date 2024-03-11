import express, { json } from "express";
import mongoose from "mongoose";
import "dotenv/config";

import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import User from "./schema/UserSchema.js";
import Referral from "./schema/ReferralSchema.js";
import Notification from "./schema/NotificationSchema.js";
import CompletedWork from "./schema/CompletedReferrel.js";
import multer from "multer";
import path from "path";
import { v2 } from "cloudinary";
import cloudinary from "cloudinary";
import fs from "fs/promises";

//schema

const server = express();

server.use(express.json());
server.use(cors());

let PORT = 5000;

mongoose.connect(process.env.DB_LOCATION, {
  autoIndex: true,
});

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

v2.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: "DX5PLGdpT-OBOxYhTlq6l5vCNxY",
});

function getCurrentDate() {
  const currentDate = new Date();
  const day = currentDate.getDate().toString().padStart(2, "0"); // Ensure two digits

  const monthIndex = currentDate.getMonth();
  const months = [
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
  ];
  const month = months[monthIndex];

  const year = currentDate.getFullYear();

  return `${day} ${month} ${year}`;
}

//middle ware

const verifyJWT = (req, res, next) => {
  const authHeader = req.headers["authorization"];

  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) {
    return res.status(401).json({
      error: "no access token",
    });
  }

  jwt.verify(token, process.env.SECRETE_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({
        error: "access token invalid",
      });
    }

    req.user = user.id;
    req.role = user.role;
    next();
  });
};

const formatDataToSend = (user) => {
  const access_token = jwt.sign(
    {
      id: user._id,
      role: user.role,
    },
    process.env.SECRETE_KEY
  );

  return {
    access_token,
    _id: user._id,
    logoURL: process.env.SERVER + "/file/" + user.logoURL,
    companyName: user.companyName,
    role: user.role,
    notificationStatus: user.notificationStatus,
    task: user.task,
  };
};

//routes



server.post(
  "/add-referral-partner",
  upload.single("logoURL"),

  async (req, res) => {
    const { _id, password, companyName, email, contact, websiteURL } = req.body;

    // If _id is present, update existing user
    if (_id) {
      // Prepare the update object
      const updateObj = {};
      if (password) {
        updateObj.password = bcrypt.hashSync(password, 10);
      }
      if (companyName) {
        updateObj.companyName = companyName;
      }
      if (email) {
        updateObj.email = email;
      }
      if (contact) {
        updateObj.contact = contact;
      }
      if (websiteURL) {
        updateObj.websiteURL = websiteURL;
      }

      if (req.file) {
        const result = await cloudinary.v2.uploader.upload(req.file.path, {
          folder: "webyAppyRefferal",
          crop: "fill",
        });

        if (result) {
          updateObj.public_url = result.public_id;
          updateObj.logoURL = result.secure_url;

          // Remove the file from the local system
          fs.rm(`uploads/${req.file.filename}`);
        } else {
          console.log("Result not obtained");
        }
      }

      // Update the user using $set
      User.findByIdAndUpdate(_id, { $set: updateObj }, { new: true })
        .then((user) => {
          if (!user) {
            return res.status(404).json({
              error: "User not found",
            });
          }
          return res.status(200).json(formatDataToSend(user));
        })
        .catch((error) => {
          console.error(error);
          return res.status(500).json({
            error: "Internal Server Error",
          });
        });
    } else {
      // If _id is not present, create a new user
      if (!req.file) {
        return res.status(404).json({
          error: "logo not found",
        });
      }

      // Validating data
      if (!companyName) {
        return res.status(403).json({
          error: "Company name is required",
        });
      }
      if (!email) {
        return res.status(403).json({ error: "Email is required" });
      }
      if (!contact) {
        return res.status(403).json({ error: "Contact number is required" });
      }
      if (!password) {
        return res.status(403).json({ error: "Password is required" });
      }

      // Hash password
      const hashPassword = bcrypt.hashSync(password, 10);

      let user = new User({
        companyName,
        email,
        password: hashPassword,
        contact,
        websiteURL,
      });

      if (req.file) {
        const result = await cloudinary.v2.uploader.upload(req.file.path, {
          folder: "webyAppyRefferal",
          crop: "fill",
        });

        if (result) {
          user.public_url = result.public_id;
          user.logoURL = result.secure_url;

          // Remove the file from the local system
          fs.rm(`uploads/${req.file.filename}`);
        } else {
          console.log("Result not obtained");
        }
      } else {
        return res.status(400).json({ message: "File not found" });
      }

      user
        .save()
        .then((u) => {
          return res.status(200).json(formatDataToSend(u));
        })
        .catch((err) => {
          if (err.code == 11000) {
            return res.status(409).json({ error: "Email already exists" });
          }
          return res.status(400).json({
            error: err.message,
          });
        });
    }
  }
);

server.post("/login", (req, res) => {
  let { email, password } = req.body;

  if (!email) {
    return res.status(409).json({
      error: "email is required",
    });
  }
  if (!password) {
    return res.status(409).json({
      error: "password is required",
    });
  }

  User.findOne({ email: email })
    .then((user) => {
      
      if (!user) {
        return res.status(403).json({
          error: "user not found, contact admin to get the credentials ",
        });
      }

      bcrypt.compare(password, user.password, (err, result) => {
        if (err) {
          return res.status(403).json({
            error: "something is wrong , please try later ",
          });
        }

        if (!result) {
          return res.status(403).json({
            error: "Incorrect password",
          });
        } else {
          return res.status(200).json(formatDataToSend(user));
        }
      });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

server.post(
  "/add-referrel",
  upload.single("logoURL"),
  verifyJWT,
  async (req, res) => {
    const userId = req.user;
    const referrelid = req.body.referrelid;

    if (referrelid) {
      const updateFields = {};

      if (req.body.companyName) updateFields.companyName = req.body.companyName;
      if (req.body.description) updateFields.description = req.body.description;
      if (req.body.mobileNumber)
        updateFields.mobileNumber = req.body.mobileNumber;
      if (req.body.email) updateFields.email = req.body.email;
      if (req.body.websiteURL) updateFields.websiteURL = req.body.websiteURL;

      if (req.file) {
        const result = await cloudinary.v2.uploader.upload(req.file.path, {
          folder: "webyAppyRefferal",
          crop: "fill",
        });

        if (result) {
          updateFields.public_url = result.public_id;
          updateFields.logoURL = result.secure_url;

          // Remove the file from the local system
          fs.rm(`uploads/${req.file.filename}`);
        }
      }

      Referral.findByIdAndUpdate(
        referrelid,
        { $set: updateFields },
        { new: true }
      )
        .then((updatedReferral) => {
          if (!updatedReferral) {
            return res.status(404).json({
              error: "Referral not found",
            });
          }

          const newNotification = new Notification({
            userId,
            referralId: updatedReferral._id,
            message: "Referral updated",
          });

          return Promise.all([
            newNotification.save(),
            User.updateMany(
              { role: "admin" },
              { $set: { notificationStatus: true } }
            ),
          ]);
        })
        .then(() => {
          res.status(200).json({ message: "Referral updated successfully" });
        })
        .catch((error) => {
          console.error("Error updating referral:", error);
          res.status(500).json({ error: error.message });
        });
    } else {
      // If referrelid is not provided, add a new referral
      const newReferral = new Referral({
        companyName: req.body.companyName,
        description: req.body.description,
        mobileNumber: req.body.mobileNumber,
        email: req.body.email,
        websiteURL: req.body.websiteURL,
        referrelBy: userId,
      });

      if (req.file) {
        const result = await cloudinary.v2.uploader.upload(req.file.path, {
          folder: "webyAppyRefferal",
          crop: "fill",
        });

        if (result) {
          newReferral.public_url = result.public_id;
          newReferral.logoURL = result.secure_url;

          // Remove the file from the local system
          fs.rm(`uploads/${req.file.filename}`);
        } else {
          console.log("Result not obtained");
        }
      } 

      // Increment the user's field by one
      User.findByIdAndUpdate(userId, { $inc: { noOfRef: 1 } })
        .then(() => {
          return newReferral.save();
        })
        .then((savedReferral) => {
          // Generate a notification
          const newNotification = new Notification({
            userId,
            referralId: savedReferral._id,
            message: "New referral added",
          });

          // Save the notification to the database
          return Promise.all([
            newNotification.save(),
            User.updateMany(
              { role: "admin" },
              { $set: { notificationStatus: true } }
            ),
          ]);
        })
        .then(() => {
          // Respond with success message for add
          res.status(200).json({ message: "Referral added successfully" });
        })
        .catch((error) => {
          console.error("Error adding/updating referral:", error);
          res.status(500).json({ error: error.message });
        });
    }
  }
);

server.post("/user-by-id", (req, res) => {
  const { _id } = req.body;
  

  User.findById(_id)
    .then((user) => {
      if (!user) {
        return res.status(404).json({
          error: "User not found",
        });
      }

      return res.status(200).json({
        email: user.email,
        _id: user._id,
        logoURL: user.logoURL,
        companyName: user.companyName,
        role: user.role,
        notificationStatus: user.notificationStatus,
        task: user.task,
      });
    })
    .catch((error) => {
      console.error(error);
      return res.status(500).json({
        error: "Internal Server Error",
      });
    });
});

// server.post("/get-all-referels", async (req, res) => {
//   let { search, page, limit } = req.body;

//   let maxlimit = limit ? limit : 10;

//   try {
//     if (!search) {
//       Referral.find({})
//         .sort({ createdAt: -1 })
//         .skip((page - 1) * maxlimit)
//         .limit(maxlimit)
//         .populate("referrelBy", "companyName")
//         .then((referrals) => {
//           const modifiedReferrals = referrals.map((ref) => {
//             let referrelByCompanyName = ref.referrelBy
//               ? ref.referrelBy.companyName
//               : "Referrer Deleted";
//             return {
//               _id: ref._id,
//               referrelBy: referrelByCompanyName,
//               companyName: ref.companyName,
//               description: ref.description,
//               mobileNumber: ref.mobileNumber,
//               email: ref.email,
//               websiteURL: ref.websiteURL,
//               logoURL: ref.logoURL,
//             };
//           });

//           return res.status(200).json(modifiedReferrals);
//         });
//     } else {
//       try {
//         const searchString = String(search);
//         console.log("Search String:", searchString); // Add logging to check search string

//         const results = await Referral.find({
//           $or: [
//             { companyName: { $regex: new RegExp(searchString, "i") } },
//             { mobileNumber: { $regex: new RegExp(searchString, "i") } },
//             { email: { $regex: new RegExp(searchString, "i") } },
//             { referrelBy: { $regex: new RegExp(searchString, "i") } },
//           ],
//         });

//         res.status(200).json(results);
//       } catch (error) {
//         console.error("Error:", error); // Add logging for error
//         res.status(500).json({ error: error.message });
//       }
//     }
//   } catch (error) {
//     console.error("Error:", error); // Add logging for error
//     return res.status(500).json({
//       error: error.message,
//     });
//   }
// });

server.post("/get-all-referels", async (req, res) => {
  let { search, page, limit } = req.body;

  let maxlimit = limit ? limit : 10;

  try {
    let query = {};

    if (search) {
      const searchString = new RegExp(search, "i");
      query.$or = [
        { companyName: { $regex: searchString } },
        { email: { $regex: searchString } },
        { mobileNumber: { $regex: searchString } },

        // Add more fields here if needed
      ];
    }

    const results = await Referral.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * maxlimit)
      .limit(maxlimit)
      .populate("referrelBy", "companyName");

    const modifiedReferrals = results.map((ref) => {
      let referrelByCompanyName = ref.referrelBy
        ? ref.referrelBy.companyName
        : "Referrer Deleted";
      return {
        _id: ref._id,
        referrelBy: referrelByCompanyName,
        companyName: ref.companyName,
        description: ref.description,
        mobileNumber: ref.mobileNumber,
        email: ref.email,
        websiteURL: ref.websiteURL,
        logoURL: ref.logoURL,
      };
    });

    res.status(200).json(modifiedReferrals);
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ error: error.message });
  }
});

server.post("/get-referel_by_id", (req, res) => {
  try {
    const { _id } = req.body;
    Referral.findById(_id)
      .populate("referrelBy", "companyName")
      .then((ref) => {
        let referrelByCompanyName = ref.referrelBy
          ? ref.referrelBy.companyName
          : "Referrer Deleted";
        const referrel = {
          _id: ref._id,
          companyName: ref.companyName,
          description: ref.description,
          mobileNumber: ref.mobileNumber,
          email: ref.email,
          referrelBy: referrelByCompanyName,
          createdAt: getCurrentDate(ref.createdAt),
          websiteURL: ref.websiteURL,
          logoURL: ref.logoURL,
        };

        return res.status(200).json(referrel);
      });
  } catch (error) {
    return res.status(500).json({
      error: error.message,
    });
  }
});

server.post("/delete-referrel", verifyJWT, (req, res) => {
  let { _id } = req.body;
  const userId = req.user;

  try {
    Referral.findByIdAndDelete(_id).then((ref) => {
      if (ref) {
        return res.status(200).json({
          message: "Referrel deleted successfully",
        });
      }
    });
  } catch (error) {
    return res.status(400).json({
      error: error.message,
    });
  }
});

server.get("/get-all-notification", verifyJWT, async (req, res) => {
  try {
    const userId = req.user;

    const notifications = await Notification.find({})
      .populate("userId", "_id companyName logoURL")
      .populate("referralId", "_id")
      .sort([["createdAt", -1]]);

    const modifiedNotifications = notifications.map((ref) => {
      let user = ref.userId ? ref.userId : null;
      let referral = ref.referralId ? ref.referralId : null;

      let modifiedUser = user
        ? {
            _id: user._id,
            companyName: user.companyName ? user.companyName : "User Deleted",
            logoURL: user.logoURL
             
          }
        : null;

      return {
        _id: ref._id,
        message: ref.message,
        userId: modifiedUser,
        referralId: referral ? { _id: referral._id } : null,
      };
    });

    await User.findByIdAndUpdate(userId, {
      notificationStatus: false,
    });

    return res.status(200).json(modifiedNotifications);
  } catch (error) {
    return res.status(500).json({
      error: error.message,
    });
  }
});

server.post("/delete-notification", verifyJWT, async (req, res) => {
  try {
    const { _id } = req.body;
    const deletedNotification = await Notification.findByIdAndDelete(_id);

    if (deletedNotification) {
      return res.status(200).json({
        message: "Deleted Successfully",
      });
    } else {
      return res.status(404).json({
        error: "Notification not found",
      });
    }
  } catch (error) {
    return res.status(500).json({
      error: error.message,
    });
  }
});

server.get("/get-all-users", (req, res) => {
  try {
    User.find({})
      .then((users) => {
        // Update logoURL for each user
        const updatedUsers = users.map((user) => {
          return {
            ...user._doc,
            logoURL: user.logoURL && user.logoURL,
          };
        });

       
        return res.status(200).json(updatedUsers);
      })
      .catch((err) => {
        return res.status(400).json({
          err: err.message,
        });
      });
  } catch (error) {
    return res.status(500).json({
      error: error.message,
    });
  }
});
server.post("/assign-task", verifyJWT, async (req, res) => {
  try {
    const { task, _id } = req.body; // Assuming tasks is the new array of tasks

    // Update the user document by assigning the new tasks array
    await User.findByIdAndUpdate(
      _id,
      { task: task } // Assigning the new tasks array
    );

    return res.status(200).json({
      message: "Tasks updated successfully",
    });
  } catch (error) {
    return res.status(500).json({
      error: error.message,
    });
  }
});

// server.post("/get-user", (req, res) => {
//   const { _id } = req.body;

//   User.findById(_id)
//     .select("-password") // Exclude the password field
//     .then((user) => {
//       if (!user) {
//         return res.status(404).json({
//           error: "User not found",
//         });
//       }

//       return res.status(200).json(user);
//     })
//     .catch((error) => {
//       console.error(error);
//       return res.status(500).json({
//         error: "Internal Server Error",
//       });
//     });
// });
server.post("/get-user", (req, res) => {
  const { _id } = req.body;

  User.findById(_id)
    .select("-password") // Exclude the password field
    .then((user) => {
      if (!user) {
        return res.status(404).json({
          error: "User not found",
        });
      }

      let logoURL = user.logoURL;

      // Check if logoURL is a local file or from api.dicebear.com
      if (!logoURL.toLowerCase().trim().includes("api.dicebear.com")) {
        logoURL = process.env.SERVER + "/file/" + logoURL;
      }

      return res.status(200).json({
        email: user.email,
        _id: user._id,
        logoURL: logoURL,
        companyName: user.companyName,
        contact: user.contact,
        address: user.address,
        websiteURL: user.websiteURL,
        role: user.role,
        notificationStatus: user.notificationStatus,
        task: user.task,
        noOfRef: user.noOfRef,
      });
    })
    .catch((error) => {
      console.error(error);
      return res.status(500).json({
        error: "Internal Server Error",
      });
    });
});

server.post("/delete-referrer", verifyJWT, (req, res) => {
  let { _id } = req.body;

  try {
    User.findByIdAndDelete(_id).then((user) => {
      if (user) {
        return res.status(200).json({
          message: "Referrer deleted successfully",
        });
      }
    });
  } catch (error) {
    return res.status(400).json({
      error: error.message,
    });
  }
});

server.post("/user-profile-by-id", (req, res) => {
  const { _id } = req.body;


  User.findById(_id)
    .then((user) => {
      if (!user) {
        return res.status(404).json({
          error: "User not found",
        });
      }

      return res.status(200).json({
        _id: user._id,
        logoURL: user.logoURL,
        companyName: user.companyName,
        role: user.role,
        notificationStatus: user.notificationStatus,
        task: user.task,
        createdAt: user.createdAt,
        contact: user.contact,
        websiteURL: user.websiteURL,
        email: user.email,
        noOfRef: user.noOfRef,
      });
    })
    .catch((error) => {
      console.error(error);
      return res.status(500).json({
        error: "Internal Server Error",
      });
    });
});

///admin panels

server.post("/get-all-admin-referels", verifyJWT, async (req, res) => {
  if (req.role !== "admin") {
    return res.status(401).json({
      message: "You don't have permission to access that route",
    });
  }

  const { workDone } = req.body;


  let query = {};

  // Check if workDone status is provided and add it to the query
  if (typeof workDone !== "undefined" && workDone !== "") {
    query.workDone = workDone;
  }

  try {
    const referrals = await Referral.find(query).populate(
      "referrelBy",
      "companyName"
    );

    const modifiedReferrals = referrals.map((ref) => {
      let referrelByCompanyName = ref.referrelBy
        ? ref.referrelBy.companyName
        : "Referrer Deleted";
      return {
        _id: ref._id,
        referrelBy: referrelByCompanyName,
        companyName: ref.companyName,
        description: ref.description,
        mobileNumber: ref.mobileNumber,
        email: ref.email,
        websiteURL: ref.websiteURL,
        workDone: ref.workDone,
        createdAt: getCurrentDate(ref.createdAt),
        logoURL: ref.logoURL
      };
    });

    return res.status(200).json(modifiedReferrals);
  } catch (error) {
    return res.status(500).json({
      error: error.message,
    });
  }
});

server.post("/change-work-status", verifyJWT, (req, res) => {
  if (req.role !== "admin") {
    return res.status(401).json({
      message: "You don't have permission to access that route",
    });
  }

  const { id: referralId } = req.body;

  try {
    Referral.findById(referralId).then((referral) => {
      if (!referral) {
        return res.status(404).json({
          message: "Referral not found",
        });
      }

      // Toggle the workDone status
      const previousWorkDoneStatus = referral.workDone;
      referral.workDone = !referral.workDone;

      referral.save().then((updatedReferral) => {
        const message = updatedReferral.workDone
          ? "Work status updated successfully"
          : "Work status reverted successfully";
        const workDone = updatedReferral.workDone;

        if (previousWorkDoneStatus !== updatedReferral.workDone) {
          if (updatedReferral.workDone) {
            // Add referral ID to completedReferral collection
            CompletedWork.create({ referralId: updatedReferral._id })
              .then(() => {
                return res.status(200).json({
                  message,
                  workDone,
                });
              })
              .catch((error) => {
                return res.status(500).json({
                  error: error.message,
                });
              });
          } else {
            // Remove referral ID from completedReferral collection
            CompletedWork.findOneAndDelete({ referralId: updatedReferral._id })
              .then(() => {
                return res.status(200).json({
                  message,
                  workDone,
                });
              })
              .catch((error) => {
                return res.status(500).json({
                  error: error.message,
                });
              });
          }
        } else {
          return res.status(200).json({
            message,
            workDone,
          });
        }
      });
    });
  } catch (error) {
    return res.status(500).json({
      error: error.message,
    });
  }
});

// Example analytics endpoint
server.get("/analytics", verifyJWT, (req, res) => {
  if (req.role !== "admin") {
    return res.status(401).json({
      message: "You don't have permission to access that route",
    });
  }

  Referral.aggregate([
    {
      $group: {
        _id: "$referrelBy",
        totalReferrals: { $sum: 1 },
      },
    },
  ])
    .then((data) => {
      // Respond with the analytical data
      res.status(200).json({ analyticsData: data });
    })
    .catch((error) => {
      console.error("Error fetching analytics data:", error);
      res.status(500).json({ error: error.message });
    });
});

server.get("/analytics/monthly", verifyJWT, (req, res) => {
  if (req.role !== "admin") {
    return res.status(401).json({
      message: "You don't have permission to access that route",
    });
  }

  // Fetch analytical data from your database, grouped by month
  Referral.aggregate([
    {
      $project: {
        month: { $month: "$createdAt" }, // Extract month from createdAt field
      },
    },
    {
      $group: {
        _id: { month: "$month" },
        totalReferrals: { $sum: 1 },
      },
    },
    {
      $sort: { "_id.month": 1 }, // Sort by month
    },
  ])
    .then((data) => {
      // Respond with the analytical data
      res.status(200).json({ monthlyAnalytics: data });
    })
    .catch((error) => {
      console.error("Error fetching monthly analytics data:", error);
      res.status(500).json({ error: error.message });
    });
});

server.get("/complete-analytics/monthly", verifyJWT, (req, res) => {
  if (req.role !== "admin") {
    return res.status(401).json({
      message: "You don't have permission to access that route",
    });
  }
  // Fetch analytical data from your database, grouped by month
  CompletedWork.aggregate([
    {
      $group: {
        _id: { $month: "$completedAt" }, // Group by month
        totalreference: { $sum: 1 }, // Count the documents for each month
      },
    },
    {
      $sort: { _id: 1 }, // Sort by month
    },
  ])
    .then((data) => {
      // Respond with the analytical data in the specified format
      const months = [
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "June",
        "July",
        "Aug",
        "Sept",
        "Oct",
        "Nov",
        "Dec",
      ];

      const formattedData = months.map((month, index) => {
        const monthData = data.find((item) => item._id === index + 1);
        return {
          totalreference: monthData ? monthData.totalreference : 0,
          month,
        };
      });

      return res.status(200).json({ formattedData });
    })
    .catch((error) => {
      console.error("Error fetching monthly analytics data:", error);
      res.status(500).json({ error: error.message });
    });
});

server.get("/get-entries-count", async (req, res) => {
  try {
    const count = await Referral.find({}).count();
    return res.status(200).json(count);
  } catch (error) {
    return res.status(400).json({
      error: error.message,
    });
  }
});

server.listen(PORT, () => {
  console.log(`listing on ${PORT}`);
});
