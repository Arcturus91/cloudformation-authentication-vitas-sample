import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  PutCommand,
  GetCommand,
  UpdateCommand,
  DeleteCommand,
  QueryCommand,
} from "@aws-sdk/lib-dynamodb";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";
import { SNSClient, SubscribeCommand } from "@aws-sdk/client-sns";

const ddbClient = new DynamoDBClient();
const ddbDocClient = DynamoDBDocumentClient.from(ddbClient);

const ROUTES = {
  SIGN_UP: "/signup",
  SIGN_IN: "/signin",
  ACCOUNT: "/account",
  PASSWORD: "/password",
  PROFILE_PICTURE: "/profile-picture",
};

const HTTP_METHODS = {
  GET: "GET",
  POST: "POST",
  PUT: "PUT",
  DELETE: "DELETE",
};

const DOCTORS_TABLE = process.env.DOCTORS_TABLE;
const PROFILE_PICTURE_BUCKET = process.env.PROFILE_PICTURE_BUCKET;
const JWT_SECRET = process.env.JWT_SECRET;
const SNS_TOPIC_ARN = process.env.SNS_TOPIC_ARN;

export const handler = async (event) => {
  try {
    const path = event.path;
    const method = event.httpMethod;

    const route = `${path}:${method}`;

    switch (route) {
      case `${ROUTES.SIGN_UP}:${HTTP_METHODS.POST}`:
        return await signUp(JSON.parse(event.body));
      case `${ROUTES.SIGN_IN}:${HTTP_METHODS.POST}`:
        return await signIn(JSON.parse(event.body));
      case `${ROUTES.ACCOUNT}:${HTTP_METHODS.DELETE}`:
        return await deleteAccount(event);
      case `${ROUTES.ACCOUNT}:${HTTP_METHODS.PUT}`:
        return await updateUserData(event);
      case `${ROUTES.PASSWORD}:${HTTP_METHODS.PUT}`:
        return await changePassword(event);
      case `${ROUTES.PROFILE_PICTURE}:${HTTP_METHODS.POST}`:
        return await uploadProfilePicture(event);
      default:
        throw new Error("Route not found");
    }
  } catch (error) {
    console.error("Error:", error);
    return {
      statusCode: 500,
      body: JSON.stringify({ message: "Internal Server Error" }),
    };
  }
};

async function signUp(userData) {
  try {
    // First, check if email already exists using the email-index
    const checkEmailParams = {
      TableName: DOCTORS_TABLE,
      IndexName: "email-index",
      KeyConditionExpression: "email = :email",
      ExpressionAttributeValues: {
        ":email": userData.email,
      },
      Select: "COUNT",
    };

    const emailCheck = await ddbDocClient.send(
      new QueryCommand(checkEmailParams)
    );

    if (emailCheck.Count > 0) {
      return {
        statusCode: 400,
        body: JSON.stringify({
          message: "Este email ya se encuentra registrado",
        }),
      };
    }

    // If email is unique, proceed with user creation
    const snsClient = new SNSClient();
    const hashedPassword = await bcrypt.hash(userData.password, 10);
    const doctorId = uuidv4();

    // Create user in DynamoDB
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
        email: userData.email,
      },
    };

    await ddbDocClient.send(new PutCommand(params));

    // Create SNS subscription for the user's email
    try {
      const subscribeCommand = new SubscribeCommand({
        TopicArn: SNS_TOPIC_ARN,
        Protocol: "email",
        Endpoint: userData.email,
        Attributes: {
          FilterPolicy: JSON.stringify({
            userType: ["doctor"],
            doctorId: [doctorId],
          }),
        },
      });

      await snsClient.send(subscribeCommand);
      console.log(`SNS subscription created for email: ${userData.email}`);
    } catch (snsError) {
      console.error("Error creating SNS subscription:", snsError);
    }

    const token = jwt.sign({ doctor_id: doctorId }, JWT_SECRET, {
      expiresIn: "1h",
    });

    return {
      statusCode: 201,
      body: JSON.stringify({
        message: "User created successfully!",
        token,
        subscriptionStatus: "Pending confirmation. Please check your email.",
      }),
      headers: {
        "Set-Cookie": `token=${token}; HttpOnly; Secure; SameSite=Strict; Max-Age=3600`,
      },
    };
  } catch (error) {
    console.error("Error in signUp:", error);
    throw error; // Let the main handler catch this
  }
}

async function signIn(credentials) {
  const params = {
    TableName: DOCTORS_TABLE,
    IndexName: "email-index",
    KeyConditionExpression: "email = :email",
    ExpressionAttributeValues: {
      ":email": credentials.email,
    },
    Select: "ALL_PROJECTED_ATTRIBUTES",
    ReturnConsumedCapacity: "TOTAL",
  };

  const command = new QueryCommand(params);

  const result = await ddbDocClient.send(command);
  if (result.Items.length === 0) {
    return {
      statusCode: 401,
      body: JSON.stringify({ message: "Invalid credentials" }),
    };
  }

  const user = result.Items[0];

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
  delete updatedData.doctor_id;
  delete updatedData.password;

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
  const s3Client = new S3Client();
  const doctorId = verifyToken(event);
  if (!doctorId)
    return {
      statusCode: 401,
      body: JSON.stringify({ message: "Unauthorized" }),
    };

  const imageData = event.body; // Assume the image is sent as base64 in the request body
  const imageBuffer = Buffer.from(imageData, "base64");

  const key = `doctors/${doctorId}/profile-picture1.png`;

  const s3Params = {
    Bucket: PROFILE_PICTURE_BUCKET,
    Key: key,
    Body: imageBuffer,
    ContentType: "image/png",
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
