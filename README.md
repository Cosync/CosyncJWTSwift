# CosyncJWTSwift

The CosyncJWTSwift package is used to add functional bindings between a Swift iOS application and the CosyncJWT service. To install this package into a Swift iOS application do the following

---

# Installation in XCode

1. In Xcode, select **File > Swift Packages > Add Package** Dependency.

2. Copy and paste the following into the search/input box, then click Next.

```
	https://github.com/Cosync/CosyncJWTSwift.git
```

3. Leave the default value of **Up to Next Major**, then click **Next**.

4. Select the Package Product; **CosyncJWTSwift**, then click **Finish**

# Function API

The CosyncJWTSwift provides a number of Swift functions 

---

## configure

The *configure()* function call is used to the CosyncJWTSwift to operate with a REST API that implements the CosyncJWT service protocol. This function should be called once at the time the application starts up.

```
	public func configure(appToken: String, cosyncRestAddress: String = "")
```

### Parameters

**appToken** : String - this contains the application token for CosyncJWT (usually retrieved from the Keys section of the Cosync Portal. 

**cosyncRestAddress** : String - this optional parameter contains the HTTPS REST API address for the CosyncJWT service. The default is 'https://rest.cosync.net' if not specified.

### Example

```
	CosyncJWTRest.shared.configure(appToken: Constants.APP_TOKEN)
```

---

## login

The *login()* function is used to login into a user's account. If the login is successful, the **error** parameter on the **completion** function will be **nil**, and the login credentials will be saved in member variables of the **CosyncJWTRest** shared object:

* **jwt**: the JWT token of the logged in user
* **accessToken**: the access token of the logged in user

If the application has enabled 2-factor google or phone verification, and the user has enabled 2-factor verification for his/her account, the **jwt** and **accessToken** will be set to **nil**, and the CosyncJWT service will set the following member variable in the **CosyncJWTRest** shared object:

* **loginToken**: signed login-token

This **loginToken** will be used by the *loginComplete()* function, which is passed a 2FA code sent to the user - either through the Google authenticator for Google Authentication or through Twilio for phone 2FA authentication.
```
	public func login(
		_ handle: String, 
		password: String, 
		onCompletion completion: @escaping (Error?) -> Void
		)
```

### Parameters

**handle** : String - this contains the user's handle or email. 

**password** : String - this contains the user's password.

**onCompletion**: Function - this is called upon completion of the login

### Example

```
	CosyncJWTRest.shared.login(email, 
		password: password, 
		onCompletion: { (error) in
		})
```
## loginComplete

The *loginComplete()* function is used to complete a login into a user's account with a 2FA code - provided by the Google authenticator or from a Twilio SMS message for phone 2FA verification. 

If the login complete is successful, the **error** parameter on the **completion** function will be **nil**, and the login credentials will be saved in member variables of the **CosyncJWTRest** shared object:

* **jwt**: the JWT token of the logged in user
* **accessToken**: the access token of the logged in user

```
    public func loginComplete(
        _ code: String, 
        onCompletion completion: @escaping (Error?) -> Void
        )
```

### Parameters

**code** : String - this contains the 6 digit code from the Google Authenticator or Twilio SMS

### Example

```
    CosyncJWTRest.shared.loginComplete(code,
        onCompletion: { (error) in
        })
```

## signup

The *signup()* function is used to signup a user with a CosyncJWT application. This function may cause the CosyncJWT service to verify the handle email of the user signing up. This verification is done by either sending a six digit verification code to the handle associated with the user account if the signup flow is `code`, otherwise it sends an email link to the handle that the user can click if the signup flow is `link`. If the signup flow is `none`, no verification of the handle is required. If the signup is successful, the *signup()* function will call a completion function with an **error** parameter set to **nil**.

Metadata associated with the user is passed in as part of the signup process in the **metadata** parameter. The metadata is passed in as JSON dictionary string. The format of the metadata is specified in the Cosync Portal for the specific application in the **JWT** tab under the *Metadata Fields* section. 

```
	public func signup(
		_ handle: String, 
		password: String, 
		metaData: String?, 
		onCompletion completion: @escaping (Error?) -> Void)
```

### Parameters

**handle** : String - this contains the user's handle or email. 

**password** : String - this contains the user's password.

**metadata** : String - JSON representation of the metadata.

**onCompletion**: Function - this is called upon completion of the login

### Example

```
	let metaData = "{\"user_data\": {\"name\": {
		\"first\": \"\(self.firstName)\", 
		\"last\": \"\(self.lastName)\"}}}"
		
	CosyncJWTRest.shared.signup(self.email, 
					password: self.password, 
					metaData: metaData, onCompletion: { (err) in

                            })

```

## completeSignup

The *completeSignup()* function is used to complete a signup of a user with a CosyncJWT application, if the developer has selected `code` as the *signup flow* within the Cosync Portal. The *completeSignup()* function should be called after the user has been emailed a six-digit code to verify his/her email handle with CosyncJWT. This function call is not necessary if the developer has selected `link` or `none` as the signup flow for the application.

If the call to *completeSignup()* is successful, the function will call a completion function with an **error** parameter set to **nil**.


```
	public func completeSignup(
		_ handle: String, 
		code: String, 
		onCompletion completion: @escaping (Error?) -> Void)
```

### Parameters

**handle** : String - this contains the user's handle or email. 

**code** : String - this contains the six-digit code sent to the user's email


### Example

```
	CosyncJWTRest.shared.completeSignup(self.email, 
		code: self.code, 
		onCompletion: { (err) in
                            
                        })

```

## invite

The *invite()* function is used to invite a user email into the CosyncJWT application. It is an alternative onboarding process to the *signup()* function. Invitation is done by the logged in user to another potential user's email. When a user is "invited" into a CosyncJWT application, he/she will receive and email to that effect. Similar the signup process, an invitation can also have attached metadata to it. The invited user email will be sent a six-digit code to validate the email at the time of onboarding during the "register()* function call.

Invite metadata associated with the user is passed in as part of the invite process in the **metadata** parameter. The metadata is passed in as JSON dictionary string. The format of the metadata is specified in the Cosync Portal for the specific application in the **JWT** tab under the *Invite Metadata Fields* section. The invite metadata could be used to encode a coupon value for the invited user, or any other data the developer sees fit.

The invitation process will also need to record the unique Realm user id of the inviting user. This is stored within the *senderUserId* parameter of the *invite()* function. 

```
	public func invite(
		_ handle: String, 
		metaData: String?, 
		senderUserId: String?, 
		onCompletion completion: @escaping (Error?) -> Void)
```

### Parameters

**handle** : String - this contains the user's handle or email. 

**metadata** : String - JSON representation of the invite metadata.

**senderUserId** : String - Realm user Id of inviting user

**onCompletion**: Function - this is called upon completion of the invite

### Example

```
	let metaData = "{\"invite_data\": {\"coupon\": \"premium\"}}"
		
	CosyncJWTRest.shared.invite(self.email, 
		metaData: metaData, 
		senderUserId: RealmManager.shared.app.currentUser?.id,
		onCompletion: { (err) in
		...
    })
```

## register

The *register()* function is used to complete the invite of a user with a CosyncJWT application. When an inviting user issues a call to the *invite()* function, the invited user email will be sent an email with a six-digit code associated with the invite. This code is passed by the invited user in the *code* parameter during a call to the *register()* function.

Metadata associated with the invited user is passed in as part of the register process in the **metadata** parameter. The metadata is passed in as JSON dictionary string. This is the invited user's metadata, which is different from the *Invite Metadata* passed in by the inviting user in the *invite(()* function call. The format of the metadata is specified in the Cosync Portal for the specific application in the **JWT** tab under the *Metadata Fields* section. 

If the call to *register()* is successful, the function will call a completion function with an **error** parameter set to **nil**.


```
	public func register(
		_ handle: String, 
		password: String, 
		metaData: String?, 
		code: String, 
		onCompletion completion: @escaping (Error?) -> Void)
```

### Parameters

**handle** : String - this contains the user's handle or email. 

**password** : String - this contains the user's password.

**metadata** : String - JSON representation of the metadata.

**code** : String - this contains the six-digit code sent to the user's email

**onCompletion**: Function - this is called upon completion of the register


### Example

```
	let metaData = "{\"user_data\": {\"name\": {
		\"first\": \"\(self.firstName)\", 
		\"last\": \"\(self.lastName)\"}}}"
		
	CosyncJWTRest.shared.register(
		self.email, 
		password: self.password, 
		metaData: metaData, 
		code: self.inviteCode, onCompletion: { (err) in
           ...                         
        })

```

## checkPassword

The *checkPassword()* function is used by the client application to check whether a password conforms to the *password filtering* parameters set for the application in the Cosync Portal. When using CosyncJWT, a developer can require that user for an application meet specific password requirements, which include:

* minimum length
* minimum upper-case letters
* minimum lower-case letters
* minimum number of digits (0…9)
* minimum special characters

The special characters include @, %, +, , /, ‘, !, #, $, ^, ?, :, (, ), [, ], ~, `, -, _, ., and ,

The *password filtering* parameters are set by the developer in the Cosync Portal, but actual password enforcement takes place at the client side. The reason for this is that passwords are sent to the CosyncJWT service as MD5 hashed strings, so there is no way to enforce this at the server level. This function is automatically called by the *signup()* function, so does not need to be called by the application code.

```
	public func checkPassword(_ password: String) -> Bool
```

### Parameters

**password** : String - this contains the user's password.

### Example

```
	if CosyncJWTRest.shared.checkPassword(self.password) {
		...
	}

```

## getUser

The *getUser()* function is used by the client application to get information about the currently logged in user to CosyncJWT. The *getUser()* function will save user information inside member variables of the **CosyncJWTRest.shared** object. These member variables include the following information:

* **handle** : String - email handle of user
* **twoFactorPhoneVerification** : Bool - whether phone 2FA is enabled for user
* **twoFactorGoogleVerification** : Bool - whether google 2FA is enabled for user
* **appId** : String - CosyncJWT app Id for user
* **phone** : String - phone number for user in E. 164 format
* **phoneVerified** : Bool - whether user phone number has been verified
* **metaData** : String - JSON string of user metadata
* **lastLogin** : Date - last login date for user

```
	public func getUser(onCompletion completion: @escaping (Error?) -> Void)
```

### Parameters

None

### Example

```
	CosyncJWTRest.shared.getUser(onCompletion: { (error) in
		...
	})

```

## getApplication

The *getApplication()* function is used by the client application to get information about the application within CosyncJWT. The *getApplication()* function will save user information inside member variables of the **CosyncJWTRest.shared** object. These member variables include the following information:

* **appName** : String - application name as stored in CosyncJWT
* **twoFactorVerification** : String - 2FA type 'phone', 'google', or 'none'
* **passwordFilter** : Bool - whether password filtering is turned on
* **passwordMinLength** : Int - minimum password length
* **passwordMinUpper** : Int - minimum number of upper case characters
* **passwordMinLower** : Int - minimum number of lower case characters
* **passwordMinDigit** : Int - minimum number of digits
* **passwordMinSpecial** : Int - minimum number of special characters
* **appData** : Date - last login date for user

```
	public func getApplication(onCompletion completion: @escaping (Error?) -> Void)
```

### Parameters

None

### Example

```
	CosyncJWTRest.shared.getApplication(onCompletion: { (error) in
		...
	})

```

## setPhone

The *setPhone()* function is used by the client application to set the user's phone number, if **twoFactorVerification** for the application is set to `phone`. The phone number should be in E.164 format, and can include the prefix '+', e.g. "+19195551212". When a phone number is set, it will be initially considered unverified. After calling the *setPhone()* function, the CosyncJWT system will send a six digit code SMS to the phone for verification. The application will then have to call the *verifyPhone()* along with the six-digit code to verify the phone on behalf of the user. 

```
	public func setPhone(
		_ phoneNumber: String, 
		onCompletion completion: @escaping (Error?) -> Void)
```

### Parameters

**phoneNumber** : String - contains the user's phone number in E.164 format

### Example

```
	CosyncJWTRest.shared.setPhone(phone, onCompletion: { (err) in
		...
    })

```

## verifyPhone

The *verifyPhone()* function is used by the client application to verify a user's phone number, after a call to the *setPhone()* function. The *verifyPhone()* must passed a six-digit code that was sent to the user's phone.

```
	public func verifyPhone(
		_ code: String, 
		onCompletion completion: @escaping (Error?)
```

### Parameters

**code** : String - six-digit code that was sent to user's phone

### Example

```
	CosyncJWTRest.shared.verifyPhone(phoneCode, onCompletion: { (err) in
		...
    })

```

## setTwoFactorPhoneVerification

The *setTwoFactorPhoneVerification()* function is used by the client application to enable two factor phone verification for the current logged in user. This function will only enable phone 2FA is the CosyncJWT application has **twoFactorVerification** set to `phone` and the user has a verified phone number.

```
	public func setTwoFactorPhoneVerification(
		_ twoFactor: Bool, 
		onCompletion completion: @escaping (Error?) -> Void)
```

### Parameters

**twoFactor** : Bool - *true* to enable phone 2FA for the user, *false* to disable it

### Example

```
	CosyncJWTRest.shared.setTwoFactorPhoneVerification(true, onCompletion: { (err) in
		...
    })

```

## setTwoFactorGoogleVerification

The *setTwoFactorGoogleVerification()* function is used by the client application to enable two factor phone verification for the current logged in user. This function will only enable google 2FA is the CosyncJWT application has **twoFactorVerification** set to `google`. After calling this function, the user will be sent an email with a bar code for the Google Authenticator application. 

Note: The Google 2FA authentication system is more secure than simple phone 2FA, because the Google codes rotate every minute. Also, the Google 2FA authentication is free is does not require a TWILIO account for SMS phone verification.

```
	public func setTwoFactorGoogleVerification(
		_ twoFactor: Bool, 
		onCompletion completion: @escaping (Error?) -> Void)
```

### Parameters

**twoFactor** : Bool - *true* to enable Google 2FA for the user, *false* to disable it

### Example

```
	CosyncJWTRest.shared.setTwoFactorGoogleVerification(true, onCompletion: { (err) in
		...
    })

```

## forgotPassword

The *forgotPassword()* function is used by the client application to enable a user to reset the password for their account. After calling this function, the user will be sent a reset password email along with a six-digit code to reset their password. The password is reset by calling the *resetPassword()* function. The user does not need to be logged in for this function to work.


```
	public func forgotPassword(
		_ handle: String, 
		onCompletion completion: @escaping (Error?) -> Void)
```

### Parameters

**handle** : String - email handle of the user to reset password for

### Example

```
	CosyncJWTRest.shared.forgotPassword(self.email, onCompletion: { (error) in
    	...                               

    })

```

## resetPassword

The *resetPassword()* function is used by the client application to reset the password for their account after issuing a *forgotPassword()* function call. The user does not need to be logged in for this function to work.


```
	public func resetPassword(
		_ handle: String, 
		password: String, 
		code: String, 
		onCompletion completion: @escaping (Error?) -> Void)
```

### Parameters

**handle** : String - email handle of the user to reset password for
**password** : String - new password for the account
**code** : String - code that was emailed the user by the *forgotPassword()* function


### Example

```
	CosyncJWTRest.shared.resetPassword(self.email, 
			password: self.password, 
			code: self.code, onCompletion: { (error) in
            	...
            })

```

## changePassword

The *changePassword()* function is used by the client application to change the password of the current logged in user. The user must be logged in for this function to work.


```
	public func changePassword(
		_ newPassword: String, 
		password: String, 
		onCompletion completion: @escaping (Error?) -> Void)
```

### Parameters

**newPassword** : String - new password for the account
**password** : String - old password for the account

### Example

```
	CosyncJWTRest.shared.changePassword(self.newPassword, 
		password: self.password, onCompletion: { (err) in
        ...
    })

```





