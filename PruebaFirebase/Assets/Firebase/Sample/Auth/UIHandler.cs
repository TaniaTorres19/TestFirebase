// Copyright 2016 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#if UNITY_IOS
using UnityEngine.SocialPlatforms.GameCenter;
#endif

namespace Firebase.Sample.Auth {
  using Firebase.Extensions;
  using System;
  using System.Collections.Generic;
  using System.Threading.Tasks;
  using UnityEngine;

  // Handler for UI buttons on the scene.  Also performs some
  // necessary setup (initializing the firebase app, etc) on
  // startup.
  public class UIHandler : MonoBehaviour {
    protected Firebase.Auth.FirebaseAuth auth;
    protected Firebase.Auth.FirebaseAuth otherAuth;
    protected Dictionary<string, Firebase.Auth.FirebaseUser> userByAuth =
      new Dictionary<string, Firebase.Auth.FirebaseUser>();

    public GUISkin fb_GUISkin;
    private string logText = "";
    protected string email = "";
    protected string password = "";
    protected string displayName = "";
    protected string phoneNumber = "";
    protected string receivedCode = "";
    protected string scope1 = "";
    protected string scope2 = "";
    protected string customParameterKey1 = "";
    protected string customParameterValue1 = "";
    protected string customParameterKey2 = "";
    protected string customParameterValue2 = "";
    // Whether to sign in / link or reauthentication *and* fetch user profile data.
    protected bool signInAndFetchProfile = false;
    // Flag set when a token is being fetched.  This is used to avoid printing the token
    // in IdTokenChanged() when the user presses the get token button.
    private bool fetchingToken = false;
    // Enable / disable password input box.
    // NOTE: In some versions of Unity the password input box does not work in
    // iOS simulators.
    public bool usePasswordInput = false;
    private Vector2 controlsScrollViewVector = Vector2.zero;
    private Vector2 scrollViewVector = Vector2.zero;
    bool UIEnabled = true;

    // Set the phone authentication timeout to a minute.
    private uint phoneAuthTimeoutMs = 60 * 1000;
    // The verification id needed along with the sent code for phone authentication.
    private string phoneAuthVerificationId;

    // Options used to setup secondary authentication object.
    private Firebase.AppOptions otherAuthOptions = new Firebase.AppOptions {
        ApiKey = "",
        AppId = "",
        ProjectId = ""
    };

    const int kMaxLogSize = 16382;
    Firebase.DependencyStatus dependencyStatus = Firebase.DependencyStatus.UnavailableOther;

    // When the app starts, check to make sure that we have
    // the required dependencies to use Firebase, and if not,
    // add them if possible.
    public virtual void Start() {
      Firebase.FirebaseApp.CheckAndFixDependenciesAsync().ContinueWithOnMainThread(task => {
        dependencyStatus = task.Result;
        if (dependencyStatus == Firebase.DependencyStatus.Available) {
          InitializeFirebase();
        } else {
          Debug.LogError(
            "Could not resolve all Firebase dependencies: " + dependencyStatus);
        }
      });
    }

    // Handle initialization of the necessary firebase modules:
    protected void InitializeFirebase() {
      DebugLog("Setting up Firebase Auth");
      auth = Firebase.Auth.FirebaseAuth.DefaultInstance;
      auth.StateChanged += AuthStateChanged;
      auth.IdTokenChanged += IdTokenChanged;
      // Specify valid options to construct a secondary authentication object.
      if (otherAuthOptions != null &&
          !(String.IsNullOrEmpty(otherAuthOptions.ApiKey) ||
            String.IsNullOrEmpty(otherAuthOptions.AppId) ||
            String.IsNullOrEmpty(otherAuthOptions.ProjectId))) {
        try {
          otherAuth = Firebase.Auth.FirebaseAuth.GetAuth(Firebase.FirebaseApp.Create(
            otherAuthOptions, "Secondary"));
          otherAuth.StateChanged += AuthStateChanged;
          otherAuth.IdTokenChanged += IdTokenChanged;
        } catch (Exception) {
          DebugLog("ERROR: Failed to initialize secondary authentication object.");
        }
      }
      AuthStateChanged(this, null);
    }

    // Exit if escape (or back, on mobile) is pressed.
    protected virtual void Update() {
      if (Input.GetKeyDown(KeyCode.Escape)) {
        Application.Quit();
      }
    }

    void OnDestroy() {
      if (auth != null) {
        auth.StateChanged -= AuthStateChanged;
        auth.IdTokenChanged -= IdTokenChanged;
        auth = null;
      }
      if (otherAuth != null) {
        otherAuth.StateChanged -= AuthStateChanged;
        otherAuth.IdTokenChanged -= IdTokenChanged;
        otherAuth = null;
      }
    }

    void DisableUI() {
      UIEnabled = false;
    }

    void EnableUI() {
      UIEnabled = true;
    }

    // Output text to the debug log text field, as well as the console.
    public void DebugLog(string s) {
      Debug.Log(s);
      logText += s + "\n";

      while (logText.Length > kMaxLogSize) {
        int index = logText.IndexOf("\n");
        logText = logText.Substring(index + 1);
      }
      scrollViewVector.y = int.MaxValue;
    }

    // Display additional user profile information.
    protected void DisplayProfile<T>(IDictionary<T, object> profile, int indentLevel) {
      string indent = new String(' ', indentLevel * 2);
      foreach (var kv in profile) {
        var valueDictionary = kv.Value as IDictionary<object, object>;
        if (valueDictionary != null) {
          DebugLog(String.Format("{0}{1}:", indent, kv.Key));
          DisplayProfile<object>(valueDictionary, indentLevel + 1);
        } else {
          DebugLog(String.Format("{0}{1}: {2}", indent, kv.Key, kv.Value));
        }
      }
    }

    // Display user information reported
    protected void DisplaySignInResult(Firebase.Auth.SignInResult result, int indentLevel) {
      string indent = new String(' ', indentLevel * 2);
      DisplayDetailedUserInfo(result.User, indentLevel);
      var metadata = result.Meta;
      if (metadata != null) {
        DebugLog(String.Format("{0}Created: {1}", indent, metadata.CreationTimestamp));
        DebugLog(String.Format("{0}Last Sign-in: {1}", indent, metadata.LastSignInTimestamp));
      }
      var info = result.Info;
      if (info != null) {
        DebugLog(String.Format("{0}Additional User Info:", indent));
        DebugLog(String.Format("{0}  User Name: {1}", indent, info.UserName));
        DebugLog(String.Format("{0}  Provider ID: {1}", indent, info.ProviderId));
        DisplayProfile<string>(info.Profile, indentLevel + 1);
      }
    }

    // Display user information.
    protected void DisplayUserInfo(Firebase.Auth.IUserInfo userInfo, int indentLevel) {
      string indent = new String(' ', indentLevel * 2);
      var userProperties = new Dictionary<string, string> {
        {"Display Name", userInfo.DisplayName},
        {"Email", userInfo.Email},
        {"Photo URL", userInfo.PhotoUrl != null ? userInfo.PhotoUrl.ToString() : null},
        {"Provider ID", userInfo.ProviderId},
        {"User ID", userInfo.UserId}
      };
      foreach (var property in userProperties) {
        if (!String.IsNullOrEmpty(property.Value)) {
          DebugLog(String.Format("{0}{1}: {2}", indent, property.Key, property.Value));
        }
      }
    }

    // Display a more detailed view of a FirebaseUser.
    protected void DisplayDetailedUserInfo(Firebase.Auth.FirebaseUser user, int indentLevel) {
      string indent = new String(' ', indentLevel * 2);
      DisplayUserInfo(user, indentLevel);
      DebugLog(String.Format("{0}Anonymous: {1}", indent, user.IsAnonymous));
      DebugLog(String.Format("{0}Email Verified: {1}", indent, user.IsEmailVerified));
      DebugLog(String.Format("{0}Phone Number: {1}", indent, user.PhoneNumber));
      var providerDataList = new List<Firebase.Auth.IUserInfo>(user.ProviderData);
      var numberOfProviders = providerDataList.Count;
      if (numberOfProviders > 0) {
        for (int i = 0; i < numberOfProviders; ++i) {
          DebugLog(String.Format("{0}Provider Data: {1}", indent, i));
          DisplayUserInfo(providerDataList[i], indentLevel + 2);
        }
      }
    }

    // Track state changes of the auth object.
    void AuthStateChanged(object sender, System.EventArgs eventArgs) {
      Firebase.Auth.FirebaseAuth senderAuth = sender as Firebase.Auth.FirebaseAuth;
      Firebase.Auth.FirebaseUser user = null;
      if (senderAuth != null) userByAuth.TryGetValue(senderAuth.App.Name, out user);
      if (senderAuth == auth && senderAuth.CurrentUser != user) {
        bool signedIn = user != senderAuth.CurrentUser && senderAuth.CurrentUser != null;
        if (!signedIn && user != null) {
          DebugLog("Signed out " + user.UserId);
        }
        user = senderAuth.CurrentUser;
        userByAuth[senderAuth.App.Name] = user;
        if (signedIn) {
          DebugLog("AuthStateChanged Signed in " + user.UserId);
          displayName = user.DisplayName ?? "";
          DisplayDetailedUserInfo(user, 1);
        }
      }
    }

    // Track ID token changes.
    void IdTokenChanged(object sender, System.EventArgs eventArgs) {
      Firebase.Auth.FirebaseAuth senderAuth = sender as Firebase.Auth.FirebaseAuth;
      if (senderAuth == auth && senderAuth.CurrentUser != null && !fetchingToken) {
        senderAuth.CurrentUser.TokenAsync(false).ContinueWithOnMainThread(
          task => DebugLog(String.Format("Token[0:8] = {0}", task.Result.Substring(0, 8))));
      }
    }

    // Log the result of the specified task, returning true if the task
    // completed successfully, false otherwise.
    protected bool LogTaskCompletion(Task task, string operation) {
      bool complete = false;
      if (task.IsCanceled) {
        DebugLog(operation + " canceled.");
      } else if (task.IsFaulted) {
        DebugLog(operation + " encounted an error.");
        foreach (Exception exception in task.Exception.Flatten().InnerExceptions) {
          string authErrorCode = "";
          Firebase.FirebaseException firebaseEx = exception as Firebase.FirebaseException;
          if (firebaseEx != null) {
            authErrorCode = String.Format("AuthError.{0}: ",
              ((Firebase.Auth.AuthError)firebaseEx.ErrorCode).ToString());
          }
          DebugLog(authErrorCode + exception.ToString());
        }
      } else if (task.IsCompleted) {
        DebugLog(operation + " completed");
        complete = true;
      }
      return complete;
    }

    // Create a user with the email and password.
    public Task CreateUserWithEmailAsync() {
      DebugLog(String.Format("Attempting to create user {0}...", email));
      DisableUI();

      // This passes the current displayName through to HandleCreateUserAsync
      // so that it can be passed to UpdateUserProfile().  displayName will be
      // reset by AuthStateChanged() when the new user is created and signed in.
      string newDisplayName = displayName;
      return auth.CreateUserWithEmailAndPasswordAsync(email, password)
        .ContinueWithOnMainThread((task) => {
          EnableUI();
          if (LogTaskCompletion(task, "User Creation")) {
            var user = task.Result;
            DisplayDetailedUserInfo(user, 1);
            return UpdateUserProfileAsync(newDisplayName: newDisplayName);
          }
          return task;
        }).Unwrap();
    }

    // Update the user's display name with the currently selected display name.
    public Task UpdateUserProfileAsync(string newDisplayName = null) {
      if (auth.CurrentUser == null) {
        DebugLog("Not signed in, unable to update user profile");
        return Task.FromResult(0);
      }
      displayName = newDisplayName ?? displayName;
      DebugLog("Updating user profile");
      DisableUI();
      return auth.CurrentUser.UpdateUserProfileAsync(new Firebase.Auth.UserProfile {
        DisplayName = displayName,
        PhotoUrl = auth.CurrentUser.PhotoUrl,
      }).ContinueWithOnMainThread(task => {
        EnableUI();
        if (LogTaskCompletion(task, "User profile")) {
          DisplayDetailedUserInfo(auth.CurrentUser, 1);
        }
      });
    }

    // Sign-in with an email and password.
    public Task SigninWithEmailAsync() {
      DebugLog(String.Format("Attempting to sign in as {0}...", email));
      DisableUI();
      if (signInAndFetchProfile) {
        return auth.SignInAndRetrieveDataWithCredentialAsync(
          Firebase.Auth.EmailAuthProvider.GetCredential(email, password)).ContinueWithOnMainThread(
            HandleSignInWithSignInResult);
      } else {
        return auth.SignInWithEmailAndPasswordAsync(email, password)
          .ContinueWithOnMainThread(HandleSignInWithUser);
      }
    }


    // Attempt to sign in anonymously.
    public Task SigninAnonymouslyAsync() {
      DebugLog("Attempting to sign anonymously...");
      DisableUI();
      return auth.SignInAnonymouslyAsync().ContinueWithOnMainThread(HandleSignInWithUser);
    }




    // Called when a sign-in without fetching profile data completes.
    void HandleSignInWithUser(Task<Firebase.Auth.FirebaseUser> task) {
      EnableUI();
      if (LogTaskCompletion(task, "Sign-in")) {
        DebugLog(String.Format("{0} signed in", task.Result.DisplayName));
      }
    }

    // Called when a sign-in with profile data completes.
    void HandleSignInWithSignInResult(Task<Firebase.Auth.SignInResult> task) {
      EnableUI();
      if (LogTaskCompletion(task, "Sign-in")) {
        DisplaySignInResult(task.Result, 1);
      }
    }




    // Determines whether another authentication object is available to focus.
    protected bool HasOtherAuth { get { return auth != otherAuth && otherAuth != null; } }

    // Swap the authentication object currently being controlled by the application.
    protected void SwapAuthFocus() {
      if (!HasOtherAuth) return;
      var swapAuth = otherAuth;
      otherAuth = auth;
      auth = swapAuth;
      DebugLog(String.Format("Changed auth from {0} to {1}",
                              otherAuth.App.Name, auth.App.Name));
    }



    // Render the log output in a scroll view.
    void GUIDisplayLog() {
      scrollViewVector = GUILayout.BeginScrollView(scrollViewVector);
      GUILayout.Label(logText);
      GUILayout.EndScrollView();
    }

    // Render the buttons and other controls.
    void GUIDisplayControls() {
      if (UIEnabled) {
        controlsScrollViewVector =
          GUILayout.BeginScrollView(controlsScrollViewVector);
        GUILayout.BeginVertical();
        GUILayout.BeginHorizontal();
        GUILayout.Label("Email:", GUILayout.Width(Screen.width * 0.20f));
        email = GUILayout.TextField(email);
        GUILayout.EndHorizontal();

        GUILayout.Space(20);

        GUILayout.BeginHorizontal();
        GUILayout.Label("Password:", GUILayout.Width(Screen.width * 0.20f));
        password = usePasswordInput ? GUILayout.PasswordField(password, '*') :
          GUILayout.TextField(password);
        GUILayout.EndHorizontal();

        GUILayout.Space(20);

        GUILayout.BeginHorizontal();
        GUILayout.Label("Display Name:", GUILayout.Width(Screen.width * 0.20f));
        displayName = GUILayout.TextField(displayName);
        GUILayout.EndHorizontal();

        GUILayout.Space(20);

        GUILayout.BeginHorizontal();
        GUILayout.Label("Phone Number:", GUILayout.Width(Screen.width * 0.20f));
        phoneNumber = GUILayout.TextField(phoneNumber);
        GUILayout.EndHorizontal();

        GUILayout.Space(20);

        GUILayout.BeginHorizontal();
        GUILayout.Label("Phone Auth Received Code:", GUILayout.Width(Screen.width * 0.20f));
        receivedCode = GUILayout.TextField(receivedCode);
        GUILayout.EndHorizontal();

        GUILayout.Space(20);

        if (GUILayout.Button("Create User")) {
          CreateUserWithEmailAsync();
        }

        if (GUILayout.Button("Sign In With Email")) {
          SigninWithEmailAsync();
        }


        GUIDisplayCustomControls();
        GUILayout.EndVertical();
        GUILayout.EndScrollView();
      }
    }

    // Overridable function to allow additional controls to be added.
    protected virtual void GUIDisplayCustomControls() { }

    // Render the GUI:
    void OnGUI() {
      GUI.skin = fb_GUISkin;
      if (dependencyStatus != Firebase.DependencyStatus.Available) {
        GUILayout.Label("One or more Firebase dependencies are not present.");
        GUILayout.Label("Current dependency status: " + dependencyStatus.ToString());
        return;
      }
      Rect logArea, controlArea;

      if (Screen.width < Screen.height) {
        // Portrait mode
        controlArea = new Rect(0.0f, 0.0f, Screen.width, Screen.height * 0.5f);
        logArea = new Rect(0.0f, Screen.height * 0.5f, Screen.width, Screen.height * 0.5f);
      } else {
        // Landscape mode
        controlArea = new Rect(0.0f, 0.0f, Screen.width * 0.5f, Screen.height);
        logArea = new Rect(Screen.width * 0.5f, 0.0f, Screen.width * 0.5f, Screen.height);
      }

      GUILayout.BeginArea(logArea);
      GUIDisplayLog();
      GUILayout.EndArea();

      GUILayout.BeginArea(controlArea);
      GUIDisplayControls();
      GUILayout.EndArea();
    }

    private class ScopedGuiEnabledModifier : IDisposable {
      private bool wasEnabled;
      public ScopedGuiEnabledModifier(bool newValue) {
        wasEnabled = GUI.enabled;
        GUI.enabled = newValue;
      }

      public void Dispose() {
        GUI.enabled = wasEnabled;
      }
    }

  }
}
