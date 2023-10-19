//
//  CSGoogleAuth.swift
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
//  Created by Tola VOEUNG  on 10/19/20.
//  Copyright © 2020 cosync. All rights reserved.
//


import Foundation
import GoogleSignIn


@available(iOS 15, *)
public class CosyncGoogleAuth: ObservableObject {
    
    
    @Published public var isLoggedIn: Bool = false
    @Published public var errorMessage: String = ""
    @Published public var idToken: String = ""
    
    public var googleClientID: String 
    public var givenName: String = ""
    public var familyName: String = ""
    public var email: String = ""
    public var userId: String = ""
    public var profilePicUrl: String = ""
     
    
    
    public init(googleClientID:String){
        self.googleClientID = googleClientID
    }
    
    public func signIn(){
        clear()
        guard let presentingViewController = (UIApplication.shared.connectedScenes.first as? UIWindowScene)?.windows.first?.rootViewController else {return}

        let config = GIDConfiguration(clientID: self.googleClientID)
        GIDSignIn.sharedInstance.configuration = config
        GIDSignIn.sharedInstance.signIn(withPresenting: presentingViewController, completion: { user, error in
          
            if let err = error?.localizedDescription{
                self.errorMessage = err
            }
            else if(GIDSignIn.sharedInstance.currentUser != nil){
                self.getUserData()
            }
            else {
                self.errorMessage = "Something went wrong"
            }
        })
    }
    
    private func getUserData(){
        
        if(GIDSignIn.sharedInstance.currentUser != nil){
            
            let user = GIDSignIn.sharedInstance.currentUser
           
            guard let user = user else { return }
           
            let givenName = user.profile?.givenName
            self.familyName = user.profile?.familyName ?? ""
            let profilePicUrl = user.profile!.imageURL(withDimension: 100)!.absoluteString
            self.givenName = givenName ?? ""
            self.email = user.profile?.email ?? ""
            self.userId = user.userID ?? ""
            self.idToken = user.idToken?.tokenString ?? ""
            self.profilePicUrl = profilePicUrl
            self.isLoggedIn = true
            
        }
    }
    
    public func signOut(){
        GIDSignIn.sharedInstance.signOut()
        clear()
    }
    
    func clear(){
        self.isLoggedIn = false
        self.idToken = ""
        self.errorMessage = ""
    }
}
