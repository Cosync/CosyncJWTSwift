# CosyncJWTSwift

The CosyncJWTSwift package is used to add functional bindings between a Swift iOS application and the CosyncJWT service. To install this package into a Swift iOS application do the following

## Installation in XCode

1. In Xcode, select **File > Swift Packages > Add Package** Dependency.

2. Copy and paste the following into the search/input box, then click Next.

```
	https://github.com/Cosync/CosyncJWTSwift.git
```

3. Leave the default value of **Up to Next Major**, then click **Next**.

4. Select the Package Product; **CosyncJWTSwift**, then click **Finish**

## Function API

The CosyncJWTSwift provides a number of Swift functions 

### configure

The *configure()* function call is used to the CosyncJWTSwift to operate with a REST API that implements the CosyncJWT service protocol. This function should be called once at the time the application starts up.

```
	public func configure(appToken: String, cosyncRestAddress: String = "")
```

#### Parameters

**appToken** : String - this contains the application token for CosyncJWT (usually retrieved from the Keys section of the Cosync Portal. 

**cosyncRestAddress** : String - this optional parameter contains the HTTPS REST API address for the CosyncJWT service. The default is 'https://rest.cosync.net' if not specified.

#### Example

```
	CosyncJWTRest.shared.configure(appToken: Constants.APP_TOKEN)
```
