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
}


public class CosyncJWTRest {
    
    // Configuration
    public var appToken: String?
    public var cosyncRestAddress: String?
        
    // Login credentials
    public var jwt: String?
    public var accessToken: String?
    public var loginToken: String?

    // complete signup credentials
    public var signedUserToken: String?
    
    // Logged in user data
    public var status: String?                      // 'active', or 'suspend'
    public var handle: String?                      // user email or phone
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
    public var signupFlow: String?
    public var appName: String?
    public var twoFactorVerification: String?
    var passwordFilter: Bool?
    var passwordMinLength: Int?
    var passwordMinUpper: Int?
    var passwordMinLower: Int?
    var passwordMinDigit: Int?
    var passwordMinSpecial: Int?
    
    var appData: [String:Any]?
    
    static let loginPath = "api/appuser/login"
    static let loginCompletePath = "api/appuser/loginComplete"
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
    static let invitePath = "api/appuser/invite"
    static let registerPath = "api/appuser/register"

    public static let shared = CosyncJWTRest()
    
    // Configure
    @MainActor public func configure(appToken: String, cosyncRestAddress: String = "") {
        self.appToken = appToken
        if cosyncRestAddress == "" {
            self.cosyncRestAddress = "https://rest.cosync.net"

        } else {
            self.cosyncRestAddress = cosyncRestAddress
        }
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
        var requestBodyComponents = URLComponents()
        requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: handle),
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

    // Singup into CosyncJWT
    @MainActor public func signup(_ handle: String, password: String, metaData: String?) async throws -> Void {
        
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
            var requestBodyComponents = URLComponents()
            if let metaData = metaData {
                requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: handle),
                                                    URLQueryItem(name: "password", value: password.md5()),
                                                    URLQueryItem(name: "metaData", value: metaData)]

            } else {
                requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: handle),
                                                    URLQueryItem(name: "password", value: password.md5())]
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
    @MainActor public func register(_ handle: String, password: String, metaData: String?, code: String)  async throws -> Void {
        
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
            
            if let metaData = metaData {
                requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: handle),
                                                    URLQueryItem(name: "password", value: password.md5()),
                                                    URLQueryItem(name: "code", value: code),
                                                    URLQueryItem(name: "metaData", value: metaData)]

            } else {
                requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: handle),
                                                    URLQueryItem(name: "password", value: password.md5()),
                                                    URLQueryItem(name: "code", value: code)]
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
        
        requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: handle),
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
        self.twoFactorPhoneVerification = nil
        self.twoFactorGoogleVerification = nil
        self.appId = nil
        self.phone = nil
        self.phoneVerified = nil
        self.metaData = nil
        self.lastLogin = nil
        
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
        
        requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: handle)]

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
        
        requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: handle),
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
        
        self.jwt = nil
        self.accessToken = nil
        self.loginToken = nil

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
        if let metaData = metaData {
            requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: handle),
                                                URLQueryItem(name: "metaData", value: metaData),
                                                URLQueryItem(name: "senderUserId", value: senderUserId)]

        } else {
            requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: handle),
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
    
    @MainActor public func logout() {
        self.jwt = nil
        self.accessToken = nil
        self.handle = nil
        self.metaData = nil
        self.lastLogin = nil
    }

}
