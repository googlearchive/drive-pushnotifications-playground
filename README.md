# Google Drive Push Notifications Playground

[![Google Drive Push Notifications Playground](https://github.com/googledrive/pushnotifications-playground/raw/master/screenshot.png)](https://pushnotificationsplayground.appspot.com/)

## Overview

**Google Drive Push Notifications Playground** is a web app that helps you to try out the features of the [Google Drive Push Notifications](https://developers.google.com/drive/push).

This sample will take you through the steps required to subscribe and unsubscribe to push notifications for changes in a specific file or any files in your Drive account. 

You can try out the Google Drive Push Notifications Playground on its [live demo instance](https://pushnotificationsplayground.appspot.com/).

## Installation and Configuration

### Create a Google APIs project and Activate the Drive API

First, you need to activate the Drive API for your app. You can do it by configuring your API project in the Google APIs Console.

- Create an API project in the [Google APIs Console](https://developers.google.com/console).
- Select the "Services" tab and enable the Drive API.
- Select the "API Access" tab in your API project, and click "Create an OAuth 2.0 client ID".
- In the Branding Information section, provide a name for your application (e.g. "CollabCube 3D"), and click Next. Providing a product logo is optional.
- In the Client ID Settings section, do the following:
  - Select Web application for the Application type
  - Click the more options link next to the heading, Your site or hostname.
  - List your hostname in the Authorized Redirect URIs and JavaScript Origins fields.
  - Click Create Client ID.
- On the same page, click on **Download JSON** to download the 'client_secrets.json' file.
- Save 'client_secrets.json' file to the root folder of this application.

### Download and extract 'google-api-python-client' library

Download the ['google-api-python-client' Google App Engine package](https://developers.google.com/api-client-library/python/start/installation#appengine) and extract it to the root folder of this application.

### Set up Google App Engine application

- Create an App Engine application in the [Google App Engine Console](https://appengine.google.com/) and note the application identifier.
- Update **application** setting in **app.yaml** file of this project with your application identifier.
- Set up Google App Engine [development environment](https://developers.google.com/appengine/docs/python/gettingstartedpython27/devenvironment) on your local machine.
- Upload and deploy your project with the following command `appcfg.py --oauth2 update .`

## Contributing

Before creating a pull request, please fill out either the individual or
corporate Contributor License Agreement.

* If you are an individual writing original source code and you're sure you
own the intellectual property, then you'll need to sign an
[individual CLA](http://code.google.com/legal/individual-cla-v1.0.html).
* If you work for a company that wants to allow you to contribute your work
to this client library, then you'll need to sign a
[corporate CLA](http://code.google.com/legal/corporate-cla-v1.0.html).

Follow either of the two links above to access the appropriate CLA and
instructions for how to sign and return it. Once we receive it, we'll add you
to the official list of contributors and be able to accept your patches.
