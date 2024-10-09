# Vitas Authentication App

## Overview
Vitas Authentication App is a serverless application built on AWS, providing authentication and user management functionalities for doctors. It uses AWS Lambda, API Gateway, DynamoDB, and S3 for secure and scalable operations.

## Features
- User SignUp and SignIn
- Account management (update user data, change password)
- Profile picture upload
- Secure authentication using JWT
- API Key protection for endpoints

## Architecture
The application is built using the following AWS services:
- AWS Lambda for serverless compute
- Amazon API Gateway for RESTful API management
- Amazon DynamoDB for data storage
- Amazon S3 for profile picture storage

## Setup and Deployment
1. Ensure you have the AWS SAM CLI installed and configured.
2. Clone this repository.
3. Navigate to the project directory.
4. Run the following commands:

## Important note
1. You will have to upload the nodemodules with the dependencies that are not aws-sdk nor nodejs built-in . I recommend to do it as a Lambda layers
