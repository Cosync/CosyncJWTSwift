//
//  RESTManager.swift
//  CosyncJWTiOS
//
//  Licensed to the Apache Software Foundation (ASF) under one
//  or more contributor license agreements.  See the NOTICE file
//  distributed with this work for additional information
//  regarding copyright ownership.  The ASF licenses this file
//  to you under the Apache License, Version 2.0 (the
//  "License"); you may not use this file except in compliance
//  with the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing,
//  software distributed under the License is distributed on an
//  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
//  KIND, either express or implied.  See the License for the
//  specific language governing permissions and limitations
//  under the License.
//
//  Created by Richard Krueger on 8/6/20.
//  Copyright © 2020 cosync. All rights reserved.
//

import Foundation
import CryptoKit

@available(macOS 10.15, *)
extension String {

    func md5() -> String {
        guard let d = self.data(using: .utf8) else { return ""}
        let digest = Insecure.MD5.hash(data: d)
        let h = digest.reduce("") { (res: String, element) in
            let hex = String(format: "%02x", element)
            //print(ch, hex)
            let  t = res + hex
            return t
        }
        return h
    }
    
    func deletingPrefix(_ prefix: String) -> String {
        guard self.hasPrefix(prefix) else { return self }
        return String(self.dropFirst(prefix.count))
    }
    
    func deletingSuffix(_ suffix: String) -> String {
        guard self.hasSuffix(suffix) else { return self }
        return String(self.dropLast(suffix.count))
    }
    
    func base64StringWithPadding() -> String {
        var stringTobeEncoded = self.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let paddingCount = self.count % 4
        for _ in 0..<paddingCount {
            stringTobeEncoded += "="
        }
        return stringTobeEncoded
    }
}


@available(macOS 10.15.0, *)
public class CosyncJWTRest {
    
    // Configuration
    public var appToken: String?
    public var cosyncRestAddress: String?
    public var rawPublicKey: String?

    // Login credentials
    public var jwt: String?
    public var accessToken: String?
    public var loginToken: String?

    // complete signup credentials
    public var signedUserToken: String?
    
    // Logged in user data
    public var status: String?                      // 'active', or 'suspend'
    public var handle: String?                      // user email or phone
    public var loginProvider: String?               // user login auth email, google, apple
    public var userName: String?                    // user name to login
    public var locale: String?                      // user locale
    public var twoFactorPhoneVerification: Bool?    // user 2-factor phone verification enabled
    public var twoFactorGoogleVerification: Bool?   // user 2-factor google verification enabled
    public var appId: String?                       // CosyncJWT app id
    public var phone: String?                       // user phone number (E 164 format)
    public var phoneVerified: Bool?                 // true if phone number is verified
    public var metaData: [String:Any]?              // user metadata
    public var lastLogin: Date?                     // last login date in UTC
    public var googleSecretKey: String?             // google secret key
    public var QRDataImage: String?                 // google QR Data Image

    // application data
    public var appData: [String:Any]?
    public var locales: [String]?
    public var signupFlow: String?
    public var appName: String?
    public var twoFactorVerification: String?
    public var userNamesEnabled:Bool?
    public var googleLoginEnabled:Bool?
    public var appleLoginEnabled:Bool?
    public var anonymousLoginEnabled: Bool?
    var passwordFilter: Bool?
    var passwordMinLength: Int?
    var passwordMinUpper: Int?
    var passwordMinLower: Int?
    var passwordMinDigit: Int?
    var passwordMinSpecial: Int?
    
    static let loginPath = "api/appuser/login"
    static let loginCompletePath = "api/appuser/loginComplete"
    static let loginAnonymousPath = "api/appuser/loginAnonymous"
    static let signupPath = "api/appuser/signup"
    static let completeSignupPath = "api/appuser/completeSignup"
    static let getUserPath = "api/appuser/getUser"
    static let setPhonePath = "api/appuser/setPhone"
    static let verifyPhonePath = "api/appuser/verifyPhone"
    static let setTwoFactorPhoneVerificationPath = "/api/appuser/setTwoFactorPhoneVerification"
    static let setTwoFactorGoogleVerificationPath = "/api/appuser/setTwoFactorGoogleVerification"
    static let forgotPasswordPath = "api/appuser/forgotPassword"
    static let resetPasswordPath = "api/appuser/resetPassword"
    static let changePasswordPath = "api/appuser/changePassword"
    static let getApplicationPath = "api/appuser/getApplication"
    static let setUserMetadataPath = "api/appuser/setUserMetadata"
    static let setUserNamePath = "api/appuser/setUserName"
    static let userNameAvailable = "api/appuser/userNameAvailable"
    static let invitePath = "api/appuser/invite"
    static let registerPath = "api/appuser/register"
    static let deleteAccountPath = "api/appuser/deleteAccount"
    static let setLocalePath = "api/appuser/setLocale"
    static let appleLoginPath = "api/appuser/appleLogin"
    static let appleSignupPath = "api/appuser/appleSignup"
    static let googleLoginPath = "api/appuser/googleLogin"
    static let googleSignupPath = "api/appuser/googleSignup"
    
    public static let shared = CosyncJWTRest()
    
    // Configure
    @MainActor public func configure(appToken: String, cosyncRestAddress: String = "", rawPublicKey: String = "") {
        self.appToken = appToken
        if cosyncRestAddress == "" {
            self.cosyncRestAddress = "https://sandbox.cosync.net"

        } else {
            self.cosyncRestAddress = cosyncRestAddress
        }
        self.rawPublicKey = rawPublicKey
    }
    
    // isValidJWT - check whether self.jwt is valid and signed correctly
    // code inspired from Muhammed Tanriverdi see link
    // https://mtanriverdi.medium.com/how-to-decode-jwt-and-validate-the-signature-in-swift-97092bd654f7
    //
    @MainActor public func isValidJWT() -> Bool {
        
        if let jwt = self.jwt,
           let rawPublicKey = self.rawPublicKey,
           !rawPublicKey.isEmpty {
            
            let parts = jwt.components(separatedBy: ".")
            
            if parts.count == 3 {
                
                let header = parts[0]
                let payload = parts[1]
                let signature = parts[2]
                
                if let decodedData = Data(base64Encoded: rawPublicKey) {
                    
                    if var publicKeyText = String(data: decodedData, encoding: .utf8) {
                        publicKeyText = publicKeyText.deletingPrefix("-----BEGIN PUBLIC KEY-----")
                        publicKeyText = publicKeyText.deletingSuffix("-----END PUBLIC KEY-----")
                        publicKeyText = String(publicKeyText.filter { !" \n\t\r".contains($0) })
                        
                        if let dataPublicKey = Data(base64Encoded: publicKeyText) {
                            
                            let publicKey: SecKey? = SecKeyCreateWithData(dataPublicKey as NSData, [
                                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                                kSecAttrKeyClass: kSecAttrKeyClassPublic
                            ] as NSDictionary, nil)
                            
                            if let publicKey = publicKey {
                                let algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
                                
                                let dataSigned = (header + "." + payload).data(using: .ascii)!
                                
                                let dataSignature = Data.init(
                                    base64Encoded: signature.base64StringWithPadding()
                                )!

                                return SecKeyVerifySignature(publicKey,
                                                                   algorithm,
                                                                   dataSigned as NSData,
                                                                   dataSignature as NSData,
                                                                   nil)
                            }
                        }
                    }
                }
            }
        }
        
        return false
    }
    
    // Login into CosyncJWT
    @MainActor public func login(_ handle: String, password: String) async throws -> Void {
        
        self.jwt = nil
        self.accessToken = nil
        self.loginToken = nil

        guard let appToken = self.appToken else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        guard let cosyncRestAddress = self.cosyncRestAddress else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        try await CosyncJWTRest.shared.getApplication()
        
        let config = URLSessionConfiguration.default

        let session = URLSession(configuration: config)
        
        let url = URL(string: "\(cosyncRestAddress)/\(CosyncJWTRest.loginPath)")!
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.allHTTPHeaderFields = ["app-token": appToken]
        
        // your post request data
        let moddedEmail = handle.replacingOccurrences(of: "+", with: "%2B")
        if !moddedEmail.contains("@"){
            if !self.userNamesEnabled! {
                throw CosyncJWTError.appIsNotSupporUserName
            }
        }
        
        var requestBodyComponents = URLComponents()
        requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: moddedEmail),
                                            URLQueryItem(name: "password", value: password.md5())]
        
        urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)
        
        do {
            let (data, response) = try await session.data(for: urlRequest)
            
            // ensure there is no error for this HTTP response
            try CosyncJWTError.checkResponse(data: data, response: response)
            
            // deserialise the data / NSData object into Dictionary [String : Any]
            guard let json = (try? JSONSerialization.jsonObject(with: data, options: JSONSerialization.ReadingOptions.mutableContainers)) as? [String: Any] else {
                throw CosyncJWTError.internalServerError
            }
            
            if let jwt = json["jwt"] as? String,
               let accessToken = json["access-token"] as? String {
                
                self.jwt = jwt
                self.accessToken = accessToken

            } else if let loginToken = json["login-token"] as? String {
                
                self.loginToken = loginToken
                
            } else {
                throw CosyncJWTError.internalServerError
            }
        }
        catch let error as CosyncJWTError {
            throw error
        }
        catch {
            throw CosyncJWTError.internalServerError
        }


    }
    
    // Login Complete into CosyncJWT
    @MainActor public func loginComplete(_ code: String) async throws -> Void {
        
        self.jwt = nil
        self.accessToken = nil
        
        guard let appToken = self.appToken else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        guard let cosyncRestAddress = self.cosyncRestAddress else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }

        guard let loginToken = self.loginToken else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }

        let config = URLSessionConfiguration.default

        let session = URLSession(configuration: config)
        
        let url = URL(string: "\(cosyncRestAddress)/\(CosyncJWTRest.loginCompletePath)")!
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.allHTTPHeaderFields = ["app-token": appToken]

        // your post request data
        var requestBodyComponents = URLComponents()
        requestBodyComponents.queryItems = [URLQueryItem(name: "loginToken", value: loginToken),
                                            URLQueryItem(name: "code", value: code)]
        
        urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)
        
        do {
            let (data, response) = try await session.data(for: urlRequest)
            
            // ensure there is no error for this HTTP response
            try CosyncJWTError.checkResponse(data: data, response: response)
            
            // deserialise the data / NSData object into Dictionary [String : Any]
            guard let json = (try? JSONSerialization.jsonObject(with: data, options: JSONSerialization.ReadingOptions.mutableContainers)) as? [String: Any] else {
                throw CosyncJWTError.internalServerError
            }
            
            if let jwt = json["jwt"] as? String,
               let accessToken = json["access-token"] as? String {
                
                self.jwt = jwt
                self.accessToken = accessToken

            } else {
                throw CosyncJWTError.internalServerError
            }
        }
        catch let error as CosyncJWTError {
            throw error
        }
        catch {
            throw CosyncJWTError.internalServerError
        }

    }
    
    // Login into CosyncJWT
    @MainActor public func loginAnonymous(_ handle: String) async throws -> Void {
        self.jwt = nil
        self.accessToken = nil
        self.loginToken = nil

        guard handle.contains("ANON_") == true else {
            throw CosyncJWTError.invalidLoginCredentials
        }
        
        guard let appToken = self.appToken else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        guard let cosyncRestAddress = self.cosyncRestAddress else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        try await CosyncJWTRest.shared.getApplication()
        
        guard self.anonymousLoginEnabled == true else {
            throw CosyncJWTError.anonymousLoginNotSupported
        }
        
       
        let config = URLSessionConfiguration.default

        let session = URLSession(configuration: config)
        
        let url = URL(string: "\(cosyncRestAddress)/\(CosyncJWTRest.loginAnonymousPath)")!
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.allHTTPHeaderFields = ["app-token": appToken]

        // your post request data
        var requestBodyComponents = URLComponents()
        requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: handle)]
        
        urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)
        
        do {
            let (data, response) = try await session.data(for: urlRequest)
            
            // ensure there is no error for this HTTP response
            try CosyncJWTError.checkResponse(data: data, response: response)
            
            // deserialise the data / NSData object into Dictionary [String : Any]
            guard let json = (try? JSONSerialization.jsonObject(with: data, options: JSONSerialization.ReadingOptions.mutableContainers)) as? [String: Any] else {
                throw CosyncJWTError.internalServerError
            }
            
            if let jwt = json["jwt"] as? String,
               let accessToken = json["access-token"] as? String {
                
                self.jwt = jwt
                self.accessToken = accessToken

            } else {
                throw CosyncJWTError.internalServerError
            }
        }
        catch let error as CosyncJWTError {
            throw error
        }
        catch {
            throw CosyncJWTError.internalServerError
        }
        
    }
    
    @MainActor public func logout() {
        self.jwt = nil
        self.accessToken = nil
        self.handle = nil
        self.userName = nil
        self.locale = nil
        self.twoFactorPhoneVerification = false
        self.twoFactorGoogleVerification = false
        self.phoneVerified = false
        self.phone = nil 
        self.loginToken = nil
        self.signedUserToken = nil
        self.metaData = nil
        self.lastLogin = nil
        self.googleSecretKey = nil
        self.QRDataImage = nil
    }

    // Singup into CosyncJWT
    @MainActor public func signup(_ handle: String, password: String, metaData: String?, locale: String? = nil) async throws -> Void {
        
        guard let appToken = self.appToken else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        guard let cosyncRestAddress = self.cosyncRestAddress else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }

        try await CosyncJWTRest.shared.getApplication()

        if self.checkPassword(password) {
            
            let config = URLSessionConfiguration.default

            let session = URLSession(configuration: config)
            
            let url = URL(string: "\(cosyncRestAddress)/\(CosyncJWTRest.signupPath)")!
            var urlRequest = URLRequest(url: url)
            urlRequest.httpMethod = "POST"
            urlRequest.allHTTPHeaderFields = ["app-token": appToken]

            // your post request data
            let moddedEmail = handle.replacingOccurrences(of: "+", with: "%2B")
            var requestBodyComponents = URLComponents()
            
            if let locale = locale {
                if let metaData = metaData {
                    requestBodyComponents.queryItems = [URLQueryItem(name: "handle",       value: moddedEmail),
                                                        URLQueryItem(name: "password", value: password.md5()),
                                                        URLQueryItem(name: "metaData", value: metaData),
                                                        URLQueryItem(name: "locale", value: locale)]

                } else {
                    requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: moddedEmail),
                                                        URLQueryItem(name: "password", value: password.md5()),
                                                        URLQueryItem(name: "locale", value: locale)]
                }
            } else {
                if let metaData = metaData {
                    requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: moddedEmail),
                                                        URLQueryItem(name: "password", value: password.md5()),
                                                        URLQueryItem(name: "metaData", value: metaData)]

                } else {
                    requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: moddedEmail),
                                                        URLQueryItem(name: "password", value: password.md5())]
                }
            }
            
            urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)
            
            do {
                let (data, response) = try await session.data(for: urlRequest)
                
                // ensure there is no error for this HTTP response
                try CosyncJWTError.checkResponse(data: data, response: response)
                
                let str = String(decoding: data, as: UTF8.self)
                
                if str != "true" && self.signupFlow != "none" {
                    throw CosyncJWTError.internalServerError
                }
                else if self.signupFlow == "none"{
                    
                    let result = Data(str.utf8)
                    
                    guard let json = (try? JSONSerialization.jsonObject(with: result, options: JSONSerialization.ReadingOptions.mutableContainers)) as? [String: Any] else {
                        throw CosyncJWTError.internalServerError
                    }
                    
                    
                    if let jwt = json["jwt"] as? String,
                       let accessToken = json["access-token"] as? String {
                        
                        self.jwt = jwt
                        self.accessToken = accessToken

                    }
                    else {
                        throw CosyncJWTError.internalServerError
                    }
                }
                
            }
            catch let error as CosyncJWTError {
                throw error
            }
            catch {
                throw CosyncJWTError.internalServerError
            }


            
        } else {
            throw CosyncJWTError.invalidPassword
        }

    }

    // register into CosyncJWT
    @MainActor public func register(_ handle: String, password: String, metaData: String?, code: String, locale: String? = nil)  async throws -> Void {
        
        self.jwt = nil
        self.accessToken = nil
        self.signedUserToken = nil

        guard let appToken = self.appToken else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        guard let cosyncRestAddress = self.cosyncRestAddress else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }

        try await CosyncJWTRest.shared.getApplication()

        if self.checkPassword(password) {
            
            let config = URLSessionConfiguration.default

            let session = URLSession(configuration: config)
            
            let url = URL(string: "\(cosyncRestAddress)/\(CosyncJWTRest.registerPath)")!
            var urlRequest = URLRequest(url: url)
            urlRequest.httpMethod = "POST"
            urlRequest.allHTTPHeaderFields = ["app-token": appToken]

            // your post request data
            var requestBodyComponents = URLComponents()
            let moddedEmail = handle.replacingOccurrences(of: "+", with: "%2B")
            if let locale = locale {
                if let metaData = metaData {
                    requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: moddedEmail),
                                                        URLQueryItem(name: "password", value: password.md5()),
                                                        URLQueryItem(name: "code", value: code),
                                                        URLQueryItem(name: "metaData", value: metaData),
                                                        URLQueryItem(name: "locale", value: locale)]

                } else {
                    requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: moddedEmail),
                                                        URLQueryItem(name: "password", value: password.md5()),
                                                        URLQueryItem(name: "code", value: code),
                                                        URLQueryItem(name: "locale", value: locale)]
                }
            } else {
                if let metaData = metaData {
                    requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: moddedEmail),
                                                        URLQueryItem(name: "password", value: password.md5()),
                                                        URLQueryItem(name: "code", value: code),
                                                        URLQueryItem(name: "metaData", value: metaData)]

                } else {
                    requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: moddedEmail),
                                                        URLQueryItem(name: "password", value: password.md5()),
                                                        URLQueryItem(name: "code", value: code)]
                }
            }
            
            urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)

            do {
                let (data, response) = try await session.data(for: urlRequest)
                
                // ensure there is no error for this HTTP response
                try CosyncJWTError.checkResponse(data: data, response: response)
                
                // deserialise the data / NSData object into Dictionary [String : Any]
                guard let json = (try? JSONSerialization.jsonObject(with: data, options: JSONSerialization.ReadingOptions.mutableContainers)) as? [String: Any] else {
                    throw CosyncJWTError.internalServerError
                }

                if let jwt = json["jwt"] as? String,
                   let accessToken = json["access-token"] as? String,
                   let signedUserToken = json["signed-user-token"] as? String {
                    
                    self.jwt = jwt
                    self.accessToken = accessToken
                    self.signedUserToken = signedUserToken
                } else {
                    throw CosyncJWTError.internalServerError
                }
                
            }
            catch let error as CosyncJWTError {
                throw error
            }
            catch {
                throw CosyncJWTError.internalServerError
            }
        } else {
            throw CosyncJWTError.invalidPassword
        }
    }
    
    
    @MainActor public func checkPassword(_ password: String) -> Bool {
        
        if let passwordFilter = self.passwordFilter,
               passwordFilter {
            
            if  let passwordMinLength = self.passwordMinLength,
                password.count < passwordMinLength {
                return false
            }
            
            if  let passwordMinUpper = self.passwordMinUpper {
                let characters = Array(password)
                var count = 0
                for c in characters {
                    let cs = String(c)
                    if cs == cs.uppercased() && cs != cs.lowercased() {
                        count += 1
                    }
                }
                if count < passwordMinUpper {
                    return false
                }
                
            }
            
            if  let passwordMinLower = self.passwordMinLower {
                let characters = Array(password)
                var count = 0
                for c in characters {
                    let cs = String(c)
                    if cs == cs.lowercased() && cs != cs.uppercased() {
                        count += 1
                    }
                }
                if count < passwordMinLower {
                    return false
                }
            }
            
            if  let passwordMinDigit = self.passwordMinDigit {
                let characters = Array(password)
                var count = 0
                for c in characters {
                    if c.isASCII && c.isNumber {
                        count += 1
                    }
                }
                if count < passwordMinDigit {
                    return false
                }
            }
                
            if  let passwordMinSpecial = self.passwordMinSpecial {
                let characterset = CharacterSet(charactersIn: "@%+\\/‘!#$^?:()[]~`-_.,")
                
                let characters = password.unicodeScalars
                var count = 0
                for c in characters {
                    if characterset.contains(c) {
                        count += 1
                    }
                }
                if count < passwordMinSpecial {
                    return false
                }
            }
        }
        
        return true
    }
    
        
    // Complete Singup into CosyncJWT
    @MainActor public func completeSignup(_ handle: String, code: String) async throws -> Void {
        self.jwt = nil
        self.accessToken = nil
        self.signedUserToken = nil

        guard let appToken = self.appToken else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        guard let cosyncRestAddress = self.cosyncRestAddress else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }

        try await CosyncJWTRest.shared.getApplication()
        
        let config = URLSessionConfiguration.default

        let session = URLSession(configuration: config)
        
        let url = URL(string: "\(cosyncRestAddress)/\(CosyncJWTRest.completeSignupPath)")!
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.allHTTPHeaderFields = ["app-token": appToken]

        // your post request data
        var requestBodyComponents = URLComponents()
        let moddedEmail = handle.replacingOccurrences(of: "+", with: "%2B")
        requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: moddedEmail),
                                            URLQueryItem(name: "code", value: code)]

        urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)
        
        do {
            let (data, response) = try await session.data(for: urlRequest)
            
            // ensure there is no error for this HTTP response
            try CosyncJWTError.checkResponse(data: data, response: response)
            
            // deserialise the data / NSData object into Dictionary [String : Any]
            guard let json = (try? JSONSerialization.jsonObject(with: data, options: JSONSerialization.ReadingOptions.mutableContainers)) as? [String: Any] else {
                throw CosyncJWTError.internalServerError
            }

            if let jwt = json["jwt"] as? String,
               let accessToken = json["access-token"] as? String,
               let signedUserToken = json["signed-user-token"] as? String {
                
                self.jwt = jwt
                self.accessToken = accessToken
                self.signedUserToken = signedUserToken
            } else {
                throw CosyncJWTError.internalServerError
            }
            
        }
        catch let error as CosyncJWTError {
            throw error
        }
        catch {
            throw CosyncJWTError.internalServerError
        }
    }
    
    // Get logged in user data from CosyncJWT
    @MainActor public func getUser() async throws -> Void {
        
        self.handle = nil
        self.userName = nil
        self.locale = nil
        self.twoFactorPhoneVerification = nil
        self.twoFactorGoogleVerification = nil
        self.appId = nil
        self.phone = nil
        self.phoneVerified = nil
        self.metaData = nil
        self.lastLogin = nil
        self.loginProvider = nil
        
        guard let cosyncRestAddress = self.cosyncRestAddress else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        guard let accessToken = self.accessToken else {
            throw CosyncJWTError.internalServerError
        }

        let config = URLSessionConfiguration.default
        config.httpAdditionalHeaders = ["access-token": accessToken]

        let session = URLSession(configuration: config)
        
        let url = URL(string: "\(cosyncRestAddress)/\(CosyncJWTRest.getUserPath)")!
        
        let urlRequest = URLRequest(url: url)

        do {
            let (data, response) = try await session.data(for: urlRequest)
            
            // ensure there is no error for this HTTP response
            try CosyncJWTError.checkResponse(data: data, response: response)
            
            // deserialise the data / NSData object into Dictionary [String : Any]
            guard let json = (try? JSONSerialization.jsonObject(with: data, options: JSONSerialization.ReadingOptions.mutableContainers)) as? [String: Any] else {
                throw CosyncJWTError.internalServerError
            }
            
            if let handle = json["handle"] as? String {
                self.handle = handle
            }
            
            if let loginProvider = json["loginProvider"] as? String {
                self.loginProvider = loginProvider
            }
            
            if let userName = json["userName"] as? String {
                self.userName = userName
            }
            
            if let locale = json["locale"] as? String {
                self.locale = locale
            }
            
            if let twoFactorPhoneVerification = json["twoFactorPhoneVerification"] as? Bool {
                self.twoFactorPhoneVerification = twoFactorPhoneVerification
            }

            if let twoFactorGoogleVerification = json["twoFactorGoogleVerification"] as? Bool {
                self.twoFactorGoogleVerification = twoFactorGoogleVerification
            }
            
            if let appId = json["appId"] as? String {
                self.appId = appId
            }
            
            if let phone = json["phone"] as? String {
                self.phone = phone
            }
            
            if let phoneVerified = json["phoneVerified"] as? Bool {
                self.phoneVerified = phoneVerified
            }
            
            if let metaData = json["metaData"] as? [String: Any] {
                self.metaData = metaData
            }
            
            if let lastLogin = json["lastLogin"] as? String {
                
                let dateFormatter = DateFormatter()
                dateFormatter.locale = .init(identifier: "en_US_POSIX")
                dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
                
                let date = dateFormatter.date(from:lastLogin)
                if let date = date {
                    self.lastLogin = date
                }
            }
            
        }
        catch let error as CosyncJWTError {
            throw error
        }
        catch {
            throw CosyncJWTError.internalServerError
        }

    }
    
    // Set the phone number for the current user from CosyncJWT
    @MainActor public func setPhone(_ phoneNumber: String) async throws -> Void {
        
        guard let cosyncRestAddress = self.cosyncRestAddress else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        guard let accessToken = self.accessToken else {
            throw CosyncJWTError.internalServerError
        }

        let config = URLSessionConfiguration.default
        config.httpAdditionalHeaders = ["access-token": accessToken]

        let session = URLSession(configuration: config)
        
        let url = URL(string: "\(cosyncRestAddress)/\(CosyncJWTRest.setPhonePath)")!
        var urlRequest = URLRequest(url: url)
        
        urlRequest.httpMethod = "POST"
        urlRequest.allHTTPHeaderFields = ["access-token": accessToken]

        // your post request data
        var requestBodyComponents = URLComponents()
        
        requestBodyComponents.queryItems = [URLQueryItem(name: "phone", value: phoneNumber)]

        urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)

        do {
            let (data, response) = try await session.data(for: urlRequest)
            
            // ensure there is no error for this HTTP response
            try CosyncJWTError.checkResponse(data: data, response: response)
            
            let str = String(decoding: data, as: UTF8.self)
            
            if str == "true" {
                self.phone = phoneNumber
            } else {
                throw CosyncJWTError.internalServerError
            }
        }
        catch let error as CosyncJWTError {
            throw error
        }
        catch {
            throw CosyncJWTError.internalServerError
        }
        
    }
    
    
    // Set the phone number for the current user from CosyncJWT
    @MainActor public func verifyPhone(_ code: String) async throws -> Void {
        
        guard let cosyncRestAddress = self.cosyncRestAddress else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        guard let accessToken = self.accessToken else {
            throw CosyncJWTError.internalServerError
        }

        let config = URLSessionConfiguration.default
        config.httpAdditionalHeaders = ["access-token": accessToken]

        let session = URLSession(configuration: config)
        
        let url = URL(string: "\(cosyncRestAddress)/\(CosyncJWTRest.verifyPhonePath)")!
        var urlRequest = URLRequest(url: url)
        
        urlRequest.httpMethod = "POST"
        urlRequest.allHTTPHeaderFields = ["access-token": accessToken]

        // your post request data
        var requestBodyComponents = URLComponents()
        
        requestBodyComponents.queryItems = [URLQueryItem(name: "code", value: code)]

        urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)

        do {
            let (data, response) = try await session.data(for: urlRequest)
            
            // ensure there is no error for this HTTP response
            try CosyncJWTError.checkResponse(data: data, response: response)
            
            let str = String(decoding: data, as: UTF8.self)
            
            if str == "true" {
                self.phoneVerified = true
            } else {
                throw CosyncJWTError.internalServerError
            }
        }
        catch let error as CosyncJWTError {
            throw error
        }
        catch {
            throw CosyncJWTError.internalServerError
        }
        
    }
    
    
    // Set two factor phone verification for the user for CosyncJWT
    @MainActor public func setTwoFactorPhoneVerification(_ twoFactor: Bool) async throws -> Void {

        guard let cosyncRestAddress = self.cosyncRestAddress else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        guard let accessToken = self.accessToken else {
            throw CosyncJWTError.internalServerError
        }

        let config = URLSessionConfiguration.default
        config.httpAdditionalHeaders = ["access-token": accessToken]

        let session = URLSession(configuration: config)
        
        let url = URL(string: "\(cosyncRestAddress)/\(CosyncJWTRest.setTwoFactorPhoneVerificationPath)")!
        var urlRequest = URLRequest(url: url)
        
        urlRequest.httpMethod = "POST"
        urlRequest.allHTTPHeaderFields = ["access-token": accessToken]

        // your post request data
        var requestBodyComponents = URLComponents()
        
        requestBodyComponents.queryItems = [URLQueryItem(name: "twoFactor", value: twoFactor ? "true" : "false")]

        urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)

        do {
            let (data, response) = try await session.data(for: urlRequest)
            
            // ensure there is no error for this HTTP response
            try CosyncJWTError.checkResponse(data: data, response: response)
            
            let str = String(decoding: data, as: UTF8.self)
            
            if str == "true" {
                self.twoFactorPhoneVerification = twoFactor
            } else {
                throw CosyncJWTError.internalServerError
            }
        }
        catch let error as CosyncJWTError {
            throw error
        }
        catch {
            throw CosyncJWTError.internalServerError
        }
    }
    
    
    // Set two factor google verification for the user for CosyncJWT
    @MainActor public func setTwoFactorGoogleVerification(_ twoFactor: Bool) async throws -> Void {
        
        guard let cosyncRestAddress = self.cosyncRestAddress else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        guard let accessToken = self.accessToken else {
            throw CosyncJWTError.internalServerError
        }

        let config = URLSessionConfiguration.default
        config.httpAdditionalHeaders = ["access-token": accessToken]

        let session = URLSession(configuration: config)
        
        let url = URL(string: "\(cosyncRestAddress)/\(CosyncJWTRest.setTwoFactorGoogleVerificationPath)")!
        var urlRequest = URLRequest(url: url)
        
        urlRequest.httpMethod = "POST"
        urlRequest.allHTTPHeaderFields = ["access-token": accessToken]

        // your post request data
        var requestBodyComponents = URLComponents()
        
        requestBodyComponents.queryItems = [URLQueryItem(name: "twoFactor", value: twoFactor ? "true" : "false")]

        urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)

        do {
            let (data, response) = try await session.data(for: urlRequest)
            
            // ensure there is no error for this HTTP response
            try CosyncJWTError.checkResponse(data: data, response: response)
            
            if twoFactor {
                // deserialise the data / NSData object into Dictionary [String : Any]
                guard let json = (try? JSONSerialization.jsonObject(with: data, options: JSONSerialization.ReadingOptions.mutableContainers)) as? [String: Any] else {
                    throw CosyncJWTError.internalServerError
                }
                
                if let googleSecretKey = json["googleSecretKey"] as? String,
                   let QRDataImage = json["QRDataImage"] as? String {
                    
                    self.twoFactorPhoneVerification = twoFactor
                    self.googleSecretKey = googleSecretKey
                    self.QRDataImage = QRDataImage
                    
                } else {
                    throw CosyncJWTError.internalServerError
                }


            } else {
                let str = String(decoding: data, as: UTF8.self)
                
                if str == "true" {
                    self.twoFactorPhoneVerification = twoFactor
                    self.googleSecretKey = nil
                    self.QRDataImage = nil
                } else {
                    throw CosyncJWTError.internalServerError
                }
            }
        }
        catch let error as CosyncJWTError {
            throw error
        }
        catch {
            throw CosyncJWTError.internalServerError
        }

    }
    
    // Forgot Password into CosyncJWT
    @MainActor public func forgotPassword(_ handle: String) async throws -> Void {
        
        guard let appToken = self.appToken else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        guard let cosyncRestAddress = self.cosyncRestAddress else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }

        let config = URLSessionConfiguration.default

        let session = URLSession(configuration: config)
        
        let url = URL(string: "\(cosyncRestAddress)/\(CosyncJWTRest.forgotPasswordPath)")!
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.allHTTPHeaderFields = ["app-token": appToken]

        // your post request data
        var requestBodyComponents = URLComponents()
        let moddedEmail = handle.replacingOccurrences(of: "+", with: "%2B")
        requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: moddedEmail)]

        urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)

        do {
            let (data, response) = try await session.data(for: urlRequest)
            
            // ensure there is no error for this HTTP response
            try CosyncJWTError.checkResponse(data: data, response: response)
            
            let str = String(decoding: data, as: UTF8.self)
            
            if str != "true" {
                throw CosyncJWTError.internalServerError
            }
        }
        catch let error as CosyncJWTError {
            throw error
        }
        catch {
            throw CosyncJWTError.internalServerError
        }
        
    }
    
    // Reset password into CosyncJWT
    @MainActor public func resetPassword(_ handle: String, password: String, code: String) async throws -> Void {
        
        guard let appToken = self.appToken else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        guard let cosyncRestAddress = self.cosyncRestAddress else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }

        let config = URLSessionConfiguration.default

        let session = URLSession(configuration: config)
        
        let url = URL(string: "\(cosyncRestAddress)/\(CosyncJWTRest.resetPasswordPath)")!
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.allHTTPHeaderFields = ["app-token": appToken]

        // your post request data
        var requestBodyComponents = URLComponents()
        let moddedEmail = handle.replacingOccurrences(of: "+", with: "%2B")
        requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: moddedEmail),
                                            URLQueryItem(name: "password", value: password.md5()),
                                            URLQueryItem(name: "code", value: code)]

        urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)

        do {
            let (data, response) = try await session.data(for: urlRequest)
            
            // ensure there is no error for this HTTP response
            try CosyncJWTError.checkResponse(data: data, response: response)
            
            let str = String(decoding: data, as: UTF8.self)
            
            if str != "true" {
                throw CosyncJWTError.internalServerError
            }
        }
        catch let error as CosyncJWTError {
            throw error
        }
        catch {
            throw CosyncJWTError.internalServerError
        }
    }
    
    // Change password into CosyncJWT
    @MainActor public func changePassword(_ newPassword: String, password: String) async throws -> Void {

        guard let cosyncRestAddress = self.cosyncRestAddress else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        guard let accessToken = self.accessToken else {
            throw CosyncJWTError.internalServerError
        }

        let config = URLSessionConfiguration.default

        let session = URLSession(configuration: config)
        
        let url = URL(string: "\(cosyncRestAddress)/\(CosyncJWTRest.changePasswordPath)")!
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.allHTTPHeaderFields = ["access-token": accessToken]

        // your post request data
        var requestBodyComponents = URLComponents()
        
        requestBodyComponents.queryItems = [URLQueryItem(name: "newPassword", value: newPassword.md5()),
                                            URLQueryItem(name: "password", value: password.md5())]

        urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)

        do {
            let (data, response) = try await session.data(for: urlRequest)
            
            // ensure there is no error for this HTTP response
            try CosyncJWTError.checkResponse(data: data, response: response)
            
            let str = String(decoding: data, as: UTF8.self)
            
            if str != "true" {
                throw CosyncJWTError.internalServerError
            }
        }
        catch let error as CosyncJWTError {
            throw error
        }
        catch {
            throw CosyncJWTError.internalServerError
        }
    }
    
    @MainActor public func getApplication() async throws -> Void {

        guard let appToken = self.appToken else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        guard let cosyncRestAddress = self.cosyncRestAddress else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        guard let url = URL(string: "\(cosyncRestAddress)/\(CosyncJWTRest.getApplicationPath)") else {
            throw CosyncJWTError.internalServerError
        }

        let config = URLSessionConfiguration.default
        config.httpAdditionalHeaders = ["app-token": appToken]

        let session = URLSession(configuration: config)

        do {
            let (data, response) = try await session.data(from: url)
            
            // ensure there is no error for this HTTP response
            try CosyncJWTError.checkResponse(data: data, response: response)
            
            // deserialise the data / NSData object into Dictionary [String : Any]
            guard let json = (try? JSONSerialization.jsonObject(with: data, options: JSONSerialization.ReadingOptions.mutableContainers)) as? [String: Any] else {
                throw CosyncJWTError.internalServerError
            }
            
            if let name = json["name"] as? String {
                self.appName = name
            }
            if let signFlow = json["signupFlow"] as? String {
                self.signupFlow = signFlow
            }
            if let anonLoginEnabled = json["anonymousLoginEnabled"] as? Bool {
                self.anonymousLoginEnabled = anonLoginEnabled
            }
            if let userNamesEnabled = json["userNamesEnabled"] as? Bool {
                self.userNamesEnabled = userNamesEnabled
            }
            if let googleLogin = json["googleLoginEnabled"] as? Bool {
                self.googleLoginEnabled = googleLogin
            }
            
            if let appleLogin = json["appleLoginEnabled"] as? Bool {
                self.appleLoginEnabled = appleLogin
            }
            
            if let twoFactorVerification = json["twoFactorVerification"] as? String {
                self.twoFactorVerification = twoFactorVerification
            }
            if let passwordFilter = json["passwordFilter"] as? Bool {
                self.passwordFilter = passwordFilter
            }
            if let passwordMinLength = json["passwordMinLength"] as? Int {
                self.passwordMinLength = passwordMinLength
            }
            if let passwordMinUpper = json["passwordMinUpper"] as? Int {
                self.passwordMinUpper = passwordMinUpper
            }
            if let passwordMinLower = json["passwordMinLower"] as? Int {
                self.passwordMinLower = passwordMinLower
            }
            if let passwordMinDigit = json["passwordMinDigit"] as? Int {
                 self.passwordMinDigit = passwordMinDigit
            }
            if let passwordMinSpecial = json["passwordMinSpecial"] as? Int {
                 self.passwordMinSpecial = passwordMinSpecial
            }

            if let appData = json["appData"] as? [String: Any] {
                self.appData = appData
            }
            
            if let locales = json["locales"] as? NSArray {
                self.locales = [String]()
                for locale in locales {
                    if let str = locale as? String {
                        self.locales?.append(str)
                    }
                }
            }

        }
        catch let error as CosyncJWTError {
            throw error
        }
        catch {
            throw CosyncJWTError.internalServerError
        }
    }
 
    // Invite into CosyncJWT
    @MainActor public func invite(_ handle: String, metaData: String?, senderUserId: String?) async throws -> Void {

        guard let cosyncRestAddress = self.cosyncRestAddress else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        guard let accessToken = self.accessToken else {
            throw CosyncJWTError.internalServerError
        }

        let config = URLSessionConfiguration.default
        let session = URLSession(configuration: config)
        
        let url = URL(string: "\(cosyncRestAddress)/\(CosyncJWTRest.invitePath)")!
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.allHTTPHeaderFields = ["access-token": accessToken]

        // your post request data
        var requestBodyComponents = URLComponents()
        let moddedEmail = handle.replacingOccurrences(of: "+", with: "%2B")
        if let metaData = metaData {
            requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: moddedEmail),
                                                URLQueryItem(name: "metaData", value: metaData),
                                                URLQueryItem(name: "senderUserId", value: senderUserId)]

        } else {
            requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: moddedEmail),
                                                URLQueryItem(name: "senderUserId", value: senderUserId)]
        }
        
        urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)
        
        do {
            let (data, response) = try await session.data(for: urlRequest)
            
            // ensure there is no error for this HTTP response
            try CosyncJWTError.checkResponse(data: data, response: response)
            
            let str = String(decoding: data, as: UTF8.self)
            
            if str != "true" {
                throw CosyncJWTError.internalServerError
            }
        }
        catch let error as CosyncJWTError {
            throw error
        }
        catch {
            throw CosyncJWTError.internalServerError
        }

    }
    
    // Delete App User Account from CosyncJWT
    @MainActor public func deleteAccount(_ handle: String?, password: String?, token:String?, provider:String?) async throws -> Void {

        guard let cosyncRestAddress = self.cosyncRestAddress else {
           throw CosyncJWTError.cosyncJWTConfiguration
        }

        guard let accessToken = self.accessToken else {
           throw CosyncJWTError.invalidAccessToken
        }

        let config = URLSessionConfiguration.default
        let session = URLSession(configuration: config)

        let url = URL(string: "\(cosyncRestAddress)/\(CosyncJWTRest.deleteAccountPath)")!
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.allHTTPHeaderFields = ["access-token": accessToken]

        var requestBodyComponents = URLComponents()
        if let handle = handle, let password = password {
            // your post request data
           
            let moddedEmail = handle.replacingOccurrences(of: "+", with: "%2B")
            
            requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: moddedEmail),
                                                URLQueryItem(name: "password", value: password.md5())]
            
        }
        else if let token = token, let provider = provider {
            requestBodyComponents.queryItems = [URLQueryItem(name: "token", value: token),
                                                URLQueryItem(name: "provider", value: provider)]
        }
        else {
            throw CosyncJWTError.invalidData
        }

        urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)

        do {
           let (data, response) = try await session.data(for: urlRequest)
           
           // ensure there is no error for this HTTP response
           try CosyncJWTError.checkResponse(data: data, response: response)
           
           let str = String(decoding: data, as: UTF8.self)
           
           if str != "true" {
               throw CosyncJWTError.internalServerError
           }
        }
        catch let error as CosyncJWTError {
           throw error
        }
        catch {
           throw CosyncJWTError.internalServerError
        }
    }
    
    // Set the locale for the current user from CosyncJWT
    @MainActor public func setLocale(_ locale: String) async throws -> Void {
        
        guard let cosyncRestAddress = self.cosyncRestAddress else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        guard let accessToken = self.accessToken else {
            throw CosyncJWTError.invalidAccessToken
        }

        let config = URLSessionConfiguration.default
        config.httpAdditionalHeaders = ["access-token": accessToken]

        let session = URLSession(configuration: config)
        
        let url = URL(string: "\(cosyncRestAddress)/\(CosyncJWTRest.setLocalePath)")!
        var urlRequest = URLRequest(url: url)
        
        urlRequest.httpMethod = "POST"
        urlRequest.allHTTPHeaderFields = ["access-token": accessToken]

        // your post request data
        var requestBodyComponents = URLComponents()
        
        requestBodyComponents.queryItems = [URLQueryItem(name: "locale", value: locale)]

        urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)

        do {
            let (data, response) = try await session.data(for: urlRequest)
            
            // ensure there is no error for this HTTP response
            try CosyncJWTError.checkResponse(data: data, response: response)
            
            let str = String(decoding: data, as: UTF8.self)
            
            if str == "true" {
                self.locale = locale
            } else {
                throw CosyncJWTError.internalServerError
            }
        }
        catch let error as CosyncJWTError {
            throw error
        }
        catch {
            throw CosyncJWTError.internalServerError
        }
        
    }
    
    // Set user meta-data CosyncJWT
    @MainActor public func setUserMetadata(_ metaData: String) async throws -> Void {

        guard let cosyncRestAddress = self.cosyncRestAddress else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        guard let accessToken = self.accessToken else {
            throw CosyncJWTError.internalServerError
        }

        let config = URLSessionConfiguration.default
        let session = URLSession(configuration: config)
        
        let url = URL(string: "\(cosyncRestAddress)/\(CosyncJWTRest.setUserMetadataPath)")!
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.allHTTPHeaderFields = ["access-token": accessToken]

        // your post request data
        var requestBodyComponents = URLComponents()

        requestBodyComponents.queryItems = [URLQueryItem(name: "metaData", value: metaData)]
        
        urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)
        
        do {
            let (data, response) = try await session.data(for: urlRequest)
            
            // ensure there is no error for this HTTP response
            try CosyncJWTError.checkResponse(data: data, response: response)
            
            let str = String(decoding: data, as: UTF8.self)
            
            if str != "true" {
                throw CosyncJWTError.internalServerError
            }
        }
        catch let error as CosyncJWTError {
            throw error
        }
        catch {
            throw CosyncJWTError.internalServerError
        }

    }
    
    // Set user name CosyncJWT
    @MainActor public func setUserName(_ userName: String) async throws -> Void {

        guard let cosyncRestAddress = self.cosyncRestAddress else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        guard let accessToken = self.accessToken else {
            throw CosyncJWTError.internalServerError
        }

        let config = URLSessionConfiguration.default
        let session = URLSession(configuration: config)
        
        let url = URL(string: "\(cosyncRestAddress)/\(CosyncJWTRest.setUserNamePath)")!
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.allHTTPHeaderFields = ["access-token": accessToken]

        // your post request data
        var requestBodyComponents = URLComponents()

        requestBodyComponents.queryItems = [URLQueryItem(name: "userName", value: userName)]
        
        urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)
        
        do {
            let (data, response) = try await session.data(for: urlRequest)
            
            // ensure there is no error for this HTTP response
            try CosyncJWTError.checkResponse(data: data, response: response)
            
            let str = String(decoding: data, as: UTF8.self)
            
            if str != "true" {
                throw CosyncJWTError.internalServerError
            }
            else {
                self.userName = userName
            }
        }
        catch let error as CosyncJWTError {
            throw error
        }
        catch {
            throw error
        }

    }
    
    // check user name available CosyncJWT
    @MainActor public func userNameAvailable(_ userName: String) async throws -> Bool {
        
        guard let cosyncRestAddress = self.cosyncRestAddress else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        guard let accessToken = self.accessToken else {
            throw CosyncJWTError.internalServerError
        }
   
        guard let url = URL(string: "\(cosyncRestAddress)/\(CosyncJWTRest.userNameAvailable)?userName=\(userName)") else {
            throw CosyncJWTError.internalServerError
        }
        
        let config = URLSessionConfiguration.default
        config.httpAdditionalHeaders = ["access-token": accessToken]

        let session = URLSession(configuration: config)
        
        do {
            let (data, response) = try await session.data(from: url)
            
            // ensure there is no error for this HTTP response
            try CosyncJWTError.checkResponse(data: data, response: response)
            
            guard let json = (try? JSONSerialization.jsonObject(with: data, options: JSONSerialization.ReadingOptions.mutableContainers)) as? [String: Any] else {
                throw CosyncJWTError.internalServerError
            }
            
            if let available = json["available"] as? Bool {
                return available
            }
            else {
                return false
            }
            
        }
        catch let error as CosyncJWTError {
            throw error
        }
        catch {
            throw error
        }

    }
    
    
    
    // Login into CosyncJWT
    @MainActor public func socialLogin(_ token: String, provider: String) async throws -> Void {
        
        self.jwt = nil
        self.accessToken = nil
        self.loginToken = nil

        guard let appToken = self.appToken else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        guard let cosyncRestAddress = self.cosyncRestAddress else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        try await CosyncJWTRest.shared.getApplication()
        
        let config = URLSessionConfiguration.default

        let session = URLSession(configuration: config)
        
        let url = URL(string: "\(cosyncRestAddress)/\(provider == "apple" ? CosyncJWTRest.appleLoginPath : CosyncJWTRest.googleLoginPath)")!
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.allHTTPHeaderFields = ["app-token": appToken]
       
        
        var requestBodyComponents = URLComponents()
        requestBodyComponents.queryItems = [URLQueryItem(name: "token", value: token)]
        
        urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)
        
        do {
            let (data, response) = try await session.data(for: urlRequest)
            
            // ensure there is no error for this HTTP response
            try CosyncJWTError.checkResponse(data: data, response: response)
            
            // deserialise the data / NSData object into Dictionary [String : Any]
            guard let json = (try? JSONSerialization.jsonObject(with: data, options: JSONSerialization.ReadingOptions.mutableContainers)) as? [String: Any] else {
                throw CosyncJWTError.internalServerError
            }
            
            if let jwt = json["jwt"] as? String,
               let accessToken = json["access-token"] as? String {
                
                self.jwt = jwt
                self.accessToken = accessToken

            } else {
                throw CosyncJWTError.internalServerError
            }
        }
        catch let error as CosyncJWTError {
             throw error
        }
        catch {
            throw CosyncJWTError.internalServerError
        }


    }
    
    
    
    // Singup into CosyncJWT with Apple
    @MainActor public func socialSignup(_ token: String, email:String, provider:String, metaData: String?, locale: String? = nil) async throws -> Void {
        
        guard let appToken = self.appToken else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }
        
        guard let cosyncRestAddress = self.cosyncRestAddress else {
            throw CosyncJWTError.cosyncJWTConfiguration
        }

        try await CosyncJWTRest.shared.getApplication()

        
            
            let config = URLSessionConfiguration.default

            let session = URLSession(configuration: config)
            
        let url = URL(string: "\(cosyncRestAddress)/\(provider == "apple" ? CosyncJWTRest.appleSignupPath : CosyncJWTRest.googleSignupPath)")!
            var urlRequest = URLRequest(url: url)
            urlRequest.httpMethod = "POST"
            urlRequest.allHTTPHeaderFields = ["app-token": appToken]

          
            var requestBodyComponents = URLComponents()
            
            if let locale = locale {
                if let metaData = metaData {
                    requestBodyComponents.queryItems = [URLQueryItem(name: "token", value: token),
                                                        URLQueryItem(name: "handle", value: email),
                                                        URLQueryItem(name: "metaData", value: metaData),
                                                        URLQueryItem(name: "locale", value: locale)]

                } else {
                    requestBodyComponents.queryItems = [URLQueryItem(name: "token", value: token),
                                                        URLQueryItem(name: "handle", value: email),
                                                        URLQueryItem(name: "locale", value: locale)]
                }
            } else {
                if let metaData = metaData {
                    requestBodyComponents.queryItems = [URLQueryItem(name: "token", value: token),
                                                        URLQueryItem(name: "handle", value: email),
                                                        URLQueryItem(name: "metaData", value: metaData)]
                } else {
                    requestBodyComponents.queryItems = [URLQueryItem(name: "token", value: token),
                                                        URLQueryItem(name: "handle", value: email)]
                }
            }
            
            urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)
            
            do {
                let (data, response) = try await session.data(for: urlRequest)
                
                // ensure there is no error for this HTTP response
                try CosyncJWTError.checkResponse(data: data, response: response)
                
                let str = String(decoding: data, as: UTF8.self)
                
                let result = Data(str.utf8)
                
                guard let json = (try? JSONSerialization.jsonObject(with: result, options: JSONSerialization.ReadingOptions.mutableContainers)) as? [String: Any] else {
                    throw CosyncJWTError.internalServerError
                }
                
                
                if let jwt = json["jwt"] as? String,
                   let accessToken = json["access-token"] as? String {
                    
                    self.jwt = jwt
                    self.accessToken = accessToken

                }
                else {
                    throw CosyncJWTError.internalServerError
                }
                 
                
            }
            catch let error as CosyncJWTError {
                throw error
            }
            catch {
                throw CosyncJWTError.internalServerError
            }


            
        

    }
    
    

}

