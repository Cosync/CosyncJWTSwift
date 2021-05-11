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
