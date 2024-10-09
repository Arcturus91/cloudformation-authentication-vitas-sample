const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const {
  DynamoDBDocumentClient,
  PutCommand,
  GetCommand,
  UpdateCommand,
  DeleteCommand,
} = require("@aws-sdk/lib-dynamodb");
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");

const ddbClient = new DynamoDBClient();
const ddbDocClient = DynamoDBDocumentClient.from(ddbClient);
const s3Client = new S3Client();

const DOCTORS_TABLE = process.env.DOCTORS_TABLE;
const PROFILE_PICTURE_BUCKET = process.env.PROFILE_PICTURE_BUCKET;
const JWT_SECRET = process.env.JWT_SECRET;

exports.handler = async (event) => {
  try {
    const path = event.path;
    const method = event.httpMethod;

    if (path === "/signup" && method === "POST") {
      return await signUp(JSON.parse(event.body));
    } else if (path === "/signin" && method === "POST") {
      return await signIn(JSON.parse(event.body));
    } else if (path === "/account" && method === "DELETE") {
      return await deleteAccount(event);
    } else if (path === "/account" && method === "PUT") {
      return await updateUserData(event);
    } else if (path === "/password" && method === "PUT") {
      return await changePassword(event);
    } else if (path === "/profile-picture" && method === "POST") {
      return await uploadProfilePicture(event);
    }

    return {
      statusCode: 404,
      body: JSON.stringify({ message: "Not Found" }),
    };
  } catch (error) {
    console.error("Error:", error);
    return {
      statusCode: 500,
      body: JSON.stringify({ message: "Internal Server Error" }),
    };
  }
};

async function signUp(userData) {
  const hashedPassword = await bcrypt.hash(userData.password, 10);
  const doctorId = uuidv4();

  const params = {
    TableName: DOCTORS_TABLE,
    Item: {
      doctor_id: doctorId,
      password: hashedPassword,
      full_name: userData.full_name,
      date_of_birth: userData.date_of_birth,
      id_number: userData.id_number,
      gender: userData.gender,
      address: userData.address,
      phone_number: userData.phone_number,
      profession: userData.profession,
      specialty: userData.specialty,
      peruvian_medical_code: userData.peruvian_medical_code,
      profile_picture: null,
    },
  };

  await ddbDocClient.send(new PutCommand(params));

  const token = jwt.sign({ doctor_id: doctorId }, JWT_SECRET, {
    expiresIn: "1h",
  });

  return {
    statusCode: 201,
    body: JSON.stringify({ message: "User created successfully", token }),
    headers: {
      "Set-Cookie": `token=${token}; HttpOnly; Secure; SameSite=Strict; Max-Age=3600`,
    },
  };
}

async function signIn(credentials) {
  const params = {
    TableName: DOCTORS_TABLE,
    Key: { doctor_id: credentials.doctor_id },
  };

  const result = await ddbDocClient.send(new GetCommand(params));
  const user = result.Item;

  if (!user || !(await bcrypt.compare(credentials.password, user.password))) {
    return {
      statusCode: 401,
      body: JSON.stringify({ message: "Invalid credentials" }),
    };
  }

  const token = jwt.sign({ doctor_id: user.doctor_id }, JWT_SECRET, {
    expiresIn: "1h",
  });

  return {
    statusCode: 200,
    body: JSON.stringify({ message: "Signed in successfully", token }),
    headers: {
      "Set-Cookie": `token=${token}; HttpOnly; Secure; SameSite=Strict; Max-Age=3600`,
    },
  };
}

async function deleteAccount(event) {
  const doctorId = verifyToken(event);
  if (!doctorId)
    return {
      statusCode: 401,
      body: JSON.stringify({ message: "Unauthorized" }),
    };

  const params = {
    TableName: DOCTORS_TABLE,
    Key: { doctor_id: doctorId },
  };

  await ddbDocClient.send(new DeleteCommand(params));

  return {
    statusCode: 200,
    body: JSON.stringify({ message: "Account deleted successfully" }),
  };
}

async function updateUserData(event) {
  const doctorId = verifyToken(event);
  if (!doctorId)
    return {
      statusCode: 401,
      body: JSON.stringify({ message: "Unauthorized" }),
    };

  const updatedData = JSON.parse(event.body);
  delete updatedData.doctor_id; // Prevent changing the doctor_id
  delete updatedData.password; // Prevent changing the password through this endpoint

  const params = {
    TableName: DOCTORS_TABLE,
    Key: { doctor_id: doctorId },
    UpdateExpression:
      "set " +
      Object.keys(updatedData)
        .map((k) => `#${k} = :${k}`)
        .join(", "),
    ExpressionAttributeNames: Object.keys(updatedData).reduce(
      (acc, k) => ({ ...acc, [`#${k}`]: k }),
      {}
    ),
    ExpressionAttributeValues: Object.entries(updatedData).reduce(
      (acc, [k, v]) => ({ ...acc, [`:${k}`]: v }),
      {}
    ),
  };

  await ddbDocClient.send(new UpdateCommand(params));

  return {
    statusCode: 200,
    body: JSON.stringify({ message: "User data updated successfully" }),
  };
}

async function changePassword(event) {
  const doctorId = verifyToken(event);
  if (!doctorId)
    return {
      statusCode: 401,
      body: JSON.stringify({ message: "Unauthorized" }),
    };

  const { oldPassword, newPassword } = JSON.parse(event.body);

  const params = {
    TableName: DOCTORS_TABLE,
    Key: { doctor_id: doctorId },
  };

  const result = await ddbDocClient.send(new GetCommand(params));
  const user = result.Item;

  if (!(await bcrypt.compare(oldPassword, user.password))) {
    return {
      statusCode: 400,
      body: JSON.stringify({ message: "Old password is incorrect" }),
    };
  }

  const hashedNewPassword = await bcrypt.hash(newPassword, 10);

  const updateParams = {
    TableName: DOCTORS_TABLE,
    Key: { doctor_id: doctorId },
    UpdateExpression: "set password = :newPassword",
    ExpressionAttributeValues: { ":newPassword": hashedNewPassword },
  };

  await ddbDocClient.send(new UpdateCommand(updateParams));

  return {
    statusCode: 200,
    body: JSON.stringify({ message: "Password changed successfully" }),
  };
}

async function uploadProfilePicture(event) {
  const doctorId = verifyToken(event);
  if (!doctorId)
    return {
      statusCode: 401,
      body: JSON.stringify({ message: "Unauthorized" }),
    };

  const imageData = event.body; // Assume the image is sent as base64 in the request body
  const imageBuffer = Buffer.from(imageData, "base64");

  const key = `${doctorId}/profile-picture.jpg`;

  const s3Params = {
    Bucket: PROFILE_PICTURE_BUCKET,
    Key: key,
    Body: imageBuffer,
    ContentType: "image/jpeg",
  };

  await s3Client.send(new PutObjectCommand(s3Params));

  const updateParams = {
    TableName: DOCTORS_TABLE,
    Key: { doctor_id: doctorId },
    UpdateExpression: "set profile_picture = :pictureUrl",
    ExpressionAttributeValues: {
      ":pictureUrl": `https://${PROFILE_PICTURE_BUCKET}.s3.amazonaws.com/${key}`,
    },
  };

  await ddbDocClient.send(new UpdateCommand(updateParams));

  return {
    statusCode: 200,
    body: JSON.stringify({ message: "Profile picture uploaded successfully" }),
  };
}

function verifyToken(event) {
  const token = event.headers.Cookie?.split(";")
    .find((c) => c.trim().startsWith("token="))
    ?.split("=")[1];
  if (!token) return null;

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return decoded.doctor_id;
  } catch (error) {
    return null;
  }
}
