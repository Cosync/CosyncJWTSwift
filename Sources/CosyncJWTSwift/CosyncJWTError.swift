//
//  RESTError.swift
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
//  Created by Richard Krueger on 8/10/20.
//  Copyright © 2020 cosync. All rights reserved.
//

import Foundation

public enum CosyncJWTError: Error {
    case cosyncJWTConfiguration
    case invalidAppToken                // 400
    case appNoLongerExist               // 401
    case appSuspended                   // 402
    case missingParameter               // 403
    case accountSuspended               // 404
    case invalidAccessToken             // 405
    case appInviteNotSupported          // 406
    case appSignupNotSupported          // 407
    case appGoogle2FactorNotSupported   // 408
    case appPhone2FactorNotSupported    // 409
    case appUserPhoneNotVerified        // 410
    case expiredSignupCode              // 411
    case phoneNumberInUse               // 412
    case internalServerError            // 500
    case invalidLoginCredentials        // 600
    case handleAlreadyRegistered        // 601
    case invalidData                    // 602
    case emailDoesNotExist              // 603
    case invalidMetaData                // 604
    case invalidPassword
    
    public var message: String {
        switch self {
        case .cosyncJWTConfiguration:
            return "CosyncJWTRest not configured"
        case .invalidAppToken:
            return "invalid app token"
        case .appNoLongerExist:
            return "app no longer exists"
        case .appSuspended:
            return "app is suspended"
        case .missingParameter:
            return "missing parameter"
        case .accountSuspended:
            return "user account is suspended"
        case .invalidAccessToken:
            return "invalid access token"
        case .appInviteNotSupported:
            return "app does not support invite"
        case .appSignupNotSupported:
            return "app does not support signup"
        case .appGoogle2FactorNotSupported:
            return "app does not support google two-factor verification"
        case .appPhone2FactorNotSupported:
            return "app does not support phone two-factor verification"
        case .appUserPhoneNotVerified:
            return "user does not have verified phone number"
        case .expiredSignupCode:
            return "expired signup code"
        case .phoneNumberInUse:
            return "phone number already in use"
        case .internalServerError:
            return "internal server error"
        case .invalidLoginCredentials:
            return "invalid login credentials"
        case .handleAlreadyRegistered:
            return "handle already registered"
        case .invalidData:
            return "invalid data"
        case .emailDoesNotExist:
            return "email does not exist"
        case .invalidMetaData:
            return "invalid metadata"
        case .invalidPassword:
            return "invalid Password"
        }
    }
    
    static func checkResponse(data: Data?, response: URLResponse?, error: Error?) -> CosyncJWTError? {
        
        if error != nil {
            return CosyncJWTError.internalServerError
        }
        if let httpResponse = response as? HTTPURLResponse {
            if httpResponse.statusCode == 200 {
                return nil
            }
            else if httpResponse.statusCode == 400 {
                if let content = data {
                    if let json = (try? JSONSerialization.jsonObject(with: content, options: JSONSerialization.ReadingOptions.mutableContainers)) as? [String: Any] {
                        if let code = json["code"] as? Int {
                            switch code {

                            case 400:
                                return CosyncJWTError.invalidAppToken
                            case 401:
                                return CosyncJWTError.appNoLongerExist
                            case 402:
                                return CosyncJWTError.appSuspended
                            case 403:
                                return CosyncJWTError.missingParameter
                            case 404:
                                return CosyncJWTError.accountSuspended
                            case 405:
                                return CosyncJWTError.invalidAccessToken
                            case 406:
                                return CosyncJWTError.appInviteNotSupported
                            case 407:
                                return CosyncJWTError.appSignupNotSupported
                            case 408:
                                return CosyncJWTError.appGoogle2FactorNotSupported
                            case 409:
                                return CosyncJWTError.appPhone2FactorNotSupported
                            case 410:
                                return CosyncJWTError.appUserPhoneNotVerified
                            case 411:
                                return CosyncJWTError.expiredSignupCode
                            case 412:
                                return CosyncJWTError.phoneNumberInUse
                            case 500:
                                return CosyncJWTError.internalServerError
                            case 600:
                                return CosyncJWTError.invalidLoginCredentials
                            case 601:
                                return CosyncJWTError.handleAlreadyRegistered
                            case 602:
                                return CosyncJWTError.invalidData
                            case 603:
                                return CosyncJWTError.emailDoesNotExist
                            case 604:
                                return CosyncJWTError.invalidMetaData
                            default:
                                return CosyncJWTError.internalServerError
                            }
                        } else {
                            return CosyncJWTError.internalServerError
                        }
                    } else {
                        return CosyncJWTError.internalServerError
                    }
                } else {
                    return CosyncJWTError.internalServerError
                }
            } else if httpResponse.statusCode == 500 {
                return CosyncJWTError.internalServerError
            }
        }
        return CosyncJWTError.internalServerError
    }
}
