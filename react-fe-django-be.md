# React + Django Integration with Scute

## Overview

 React: Your react frontend
    Backend: Your Django backend
    Scute: Scute API

    Note over React,Scute: Initial Authentication
    React->>Scute: Get Session
    Scute-->>React: Session Status + Tokens (access, refresh, csrf)
    React->>Backend: POST /api/auth/login (access_token + csrf)
    Backend-->>React: Set HTTP-only cookies (refresh_token, csrf)

    Note over React,Backend: API Calls
    React->>Backend: API Request + Access Token + X-CSRF-Token
    Backend-->>React: Protected Data

    Note over React,Backend: Token Refresh
    React->>Backend: POST /api/auth/refresh + X-CSRF-Token
    Backend->>Scute: Use refresh token to get new tokens
    Scute-->>Backend: New tokens
    Backend-->>React: New access token + Update cookies

## Security Warning

When implementing authentication in a browser-based application:

1. **Refresh Token Security:**
   - There is NO completely secure way to store refresh tokens in a browser
   - All browser storage methods (localStorage, sessionStorage, JS-accessible cookies) are vulnerable to XSS attacks
   - Consider shorter token lifetimes and more frequent re-authentication for sensitive applications

2. **Alternative Approaches:**
   - For higher security requirements, consider implementing refresh token rotation through your backend
   - Or avoid refresh tokens entirely and require re-authentication when access tokens expire
   - Use shorter access token lifetimes to balance security and user experience

## 1. React Frontend Implementation

```typescript
// src/auth/ScuteAuth.tsx
import { 
  ScuteClient, 
  type ScuteTokenPayload 
} from "@scute/js-core";

const scuteClient = new ScuteClient({
  appId: process.env.REACT_APP_SCUTE_APP_ID
});

export const ScuteAuthProvider = ({ children }) => {
  const [authState, setAuthState] = useState({
    isAuthenticated: false,
    user: null,
    loading: true,
    accessToken: null,
    refreshToken: null,
    csrfToken: null
  });

  useEffect(() => {
    const initAuth = async () => {
      const { data, error } = await scuteClient.getSession();
      
      if (data?.session && data.session.status === "authenticated") {
        setAuthState({
          isAuthenticated: true,
          user: data.session.user,
          loading: false,
          accessToken: data.session.accessToken,
          refreshToken: data.session.refreshToken,
          csrfToken: data.session.csrfToken
        });
      } else {
        setAuthState({
          isAuthenticated: false,
          user: null,
          loading: false,
          accessToken: null,
          refreshToken: null,
          csrfToken: null
        });
      }
    };

    initAuth();
  }, []);

  // Helper function to validate tokens with Django backend
  const validateWithBackend = async (accessToken: string, csrfToken: string) => {
    try {
      const response = await fetch('/api/auth/validate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
          'X-CSRF-Token': csrfToken
        }
      });

      if (!response.ok) {
        throw new Error('Token validation failed');
      }

      const data = await response.json();
      return data;
    } catch (error) {
      console.error('Validation error:', error);
      throw error;
    }
  };

  // Function to refresh tokens
  const refreshTokens = async () => {
    try {
      const { data, error } = await scuteClient.refreshSession();
      
      if (error) throw error;

      setAuthState(prev => ({
        ...prev,
        accessToken: data.session.accessToken,
        refreshToken: data.session.refreshToken,
        csrfToken: data.session.csrfToken
      }));

      return data.session;
    } catch (error) {
      console.error('Token refresh error:', error);
      throw error;
    }
  };

  // API request wrapper with token refresh
  const apiRequest = async (url: string, options: RequestInit = {}) => {
    try {
      // Add auth headers
      const headers = {
        ...options.headers,
        'Authorization': `Bearer ${authState.accessToken}`,
        'X-CSRF-Token': authState.csrfToken
      };

      const response = await fetch(url, { ...options, headers });

      // If token expired, refresh and retry
      if (response.status === 401) {
        const newSession = await refreshTokens();
        
        headers['Authorization'] = `Bearer ${newSession.accessToken}`;
        headers['X-CSRF-Token'] = newSession.csrfToken;
        
        return fetch(url, { ...options, headers });
      }

      return response;
    } catch (error) {
      console.error('API request error:', error);
      throw error;
    }
  };

  return (
    <ScuteAuthContext.Provider 
      value={{
        ...authState,
        refreshTokens,
        apiRequest
      }}
    >
      {children}
    </ScuteAuthContext.Provider>
  );
};

// Hook to use auth context
export const useScuteAuth = () => {
  const context = useContext(ScuteAuthContext);
  if (!context) {
    throw new Error('useScuteAuth must be used within ScuteAuthProvider');
  }
  return context;
};
```

## 2. Django Backend Implementation

```python
# backend/auth.py
from django.http import JsonResponse
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import requests
import jwt

class ScuteAuth:
    REFRESH_TOKEN_COOKIE = 'scute_refresh_token'
    CSRF_TOKEN_COOKIE = 'scute_csrf_token'
    
    @staticmethod
    def set_auth_cookies(response, refresh_token, csrf_token):
        """Set refresh token and CSRF token in HTTP-only cookies"""
        # Set refresh token
        response.set_cookie(
            ScuteAuth.REFRESH_TOKEN_COOKIE,
            refresh_token,
            httponly=True,
            secure=True,
            samesite='Lax',
            max_age=30 * 24 * 60 * 60  # 30 days
        )
        
        # Set CSRF token
        response.set_cookie(
            ScuteAuth.CSRF_TOKEN_COOKIE,
            csrf_token,
            httponly=True,
            secure=True,
            samesite='Lax',
            max_age=30 * 24 * 60 * 60  # 30 days
        )

    @staticmethod
    def get_tokens(request):
        """Get refresh and CSRF tokens from cookies"""
        return {
            'refresh_token': request.COOKIES.get(ScuteAuth.REFRESH_TOKEN_COOKIE),
            'csrf_token': request.COOKIES.get(ScuteAuth.CSRF_TOKEN_COOKIE)
        }

    @staticmethod
    def clear_auth_cookies(response):
        """Clear both refresh and CSRF token cookies"""
        response.delete_cookie(ScuteAuth.REFRESH_TOKEN_COOKIE)
        response.delete_cookie(ScuteAuth.CSRF_TOKEN_COOKIE)

    @staticmethod
    def verify_csrf_token(request):
        """Verify that the CSRF token in the header matches the cookie"""
        header_token = request.headers.get('X-CSRF-Token')
        cookie_token = request.COOKIES.get(ScuteAuth.CSRF_TOKEN_COOKIE)
        
        if not header_token or not cookie_token:
            return False
            
        return header_token == cookie_token

class LoginView(APIView):
    def post(self, request):
        access_token = request.data.get('access_token')
        refresh_token = request.data.get('refresh_token')
        csrf_token = request.data.get('csrf_token')
        
        if not all([access_token, refresh_token, csrf_token]):
            return Response(
                {"error": "access_token, refresh_token, and csrf_token are required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            # Verify access token (optional but recommended)
            user_data = jwt.decode(
                access_token, 
                options={"verify_signature": False}
            )
            
            # Create response with new access token
            response = Response({
                'message': 'Login successful',
                'user': user_data
            })
            
            # Store both refresh token and CSRF token in HTTP-only cookies
            ScuteAuth.set_auth_cookies(response, refresh_token, csrf_token)
            
            return response
            
        except Exception as e:
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_401_UNAUTHORIZED
            )

class RefreshView(APIView):
    def post(self, request):
        # First verify CSRF token
        if not ScuteAuth.verify_csrf_token(request):
            return Response(
                {"error": "Invalid CSRF token"}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        tokens = ScuteAuth.get_tokens(request)
        refresh_token = tokens['refresh_token']
        
        if not refresh_token:
            return Response(
                {"error": "No refresh token found"}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        try:
            # Get new tokens from Scute
            scute_response = requests.post(
                f"{settings.SCUTE_API_URL}/auth/refresh",
                headers={
                    'Content-Type': 'application/json',
                    'X-Scute-App-Id': settings.SCUTE_APP_ID
                },
                json={'refresh_token': refresh_token}
            )
            
            if scute_response.status_code != 200:
                # Clear invalid tokens
                response = Response(
                    {"error": "Invalid refresh token"}, 
                    status=status.HTTP_401_UNAUTHORIZED
                )
                ScuteAuth.clear_auth_cookies(response)
                return response
                
            tokens = scute_response.json()
            
            # Create response with new access token
            response = Response({
                'access_token': tokens['access_token']
            })
            
            # Update both refresh and CSRF tokens if provided
            if 'refresh_token' in tokens and 'csrf_token' in tokens:
                ScuteAuth.set_auth_cookies(
                    response, 
                    tokens['refresh_token'],
                    tokens['csrf_token']
                )
            
            return response
            
        except Exception as e:
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

# urls.py
from django.urls import path
from .views import LoginView, RefreshView

urlpatterns = [
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/refresh/', RefreshView.as_view(), name='refresh'),
]
```

## 3. Usage Example

```typescript
// src/components/ProtectedComponent.tsx
import { useScuteAuth } from '../auth/ScuteAuth';

const ProtectedComponent = () => {
  const { isAuthenticated, user, apiRequest } = useScuteAuth();

  const fetchProtectedData = async () => {
    try {
      const response = await apiRequest('/api/protected-data');
      const data = await response.json();
      // Handle data
    } catch (error) {
      // Handle error
    }
  };

  if (!isAuthenticated) {
    return <div>log in</div>;
  }

  return (
    <div>
      <h1>Welcome {user.name}</h1>
      <button onClick={fetchProtectedData}>
        Fetch Protected Data
      </button>
    </div>
  );
};
```

## Key Security Considerations

1. **Token Storage**
   - Access tokens are stored in localStorage (frontend)
   - CSRF tokens are stored in both localStorage and HTTP-only cookie for double-submit validation
   - Refresh tokens are stored in HTTP-only cookie (backend)
   - Never store refresh token in browser storage

2. **Token Refresh**
   - Backend handles refresh token exchange with Scute
   - Frontend only sees access tokens
   - CSRF validation required for refresh
   - Automatic refresh on 401 responses

3. **CSRF Protection**
   - Double-submit cookie pattern
   - CSRF token required for all state-changing requests
   - Token validation on both frontend and backend

4. **Error Handling**
   - Proper error handling for token validation
   - Automatic logout on critical auth errors
   - Clear error messages for debugging

## Best Practices

1. Always use HTTPS in production
2. Implement proper token refresh logic
3. Handle token expiration gracefully
4. Validate tokens on both frontend and backend
5. Use secure session cookies for refresh tokens
6. Implement CSRF protection
7. Clear all tokens on logout
8. Add proper error handling
9. Use environment variables for sensitive data
10. Regular security audits and updates 

## 4. Secure Refresh Token Storage with Django

### Django Implementation

```python
# backend/auth.py
from django.http import JsonResponse
from django.conf import settings
from functools import wraps
import jwt
from jwt.exceptions import InvalidTokenError

class TokenManager:
    REFRESH_TOKEN_COOKIE = 'scute_refresh_token'
    CSRF_TOKEN_COOKIE = 'scute_csrf_token'
    
    @staticmethod
    def set_refresh_token_cookie(response, refresh_token):
        response.set_cookie(
            TokenManager.REFRESH_TOKEN_COOKIE,
            refresh_token,
            httponly=True,  # Cannot be accessed by JavaScript
            secure=True,    # Only sent over HTTPS
            samesite='Lax', # CSRF protection
            max_age=7 * 24 * 60 * 60,  # 7 days
            domain=settings.SESSION_COOKIE_DOMAIN,
            path='/auth/refresh'  # Only sent to refresh endpoint
        )
    
    @staticmethod
    def clear_refresh_token_cookie(response):
        response.delete_cookie(
            TokenManager.REFRESH_TOKEN_COOKIE,
            domain=settings.SESSION_COOKIE_DOMAIN,
            path='/auth/refresh'
        )

# views.py
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_http_methods

@require_http_methods(["POST"])
def handle_login(request):
    try:
        # Get tokens from request body
        data = json.loads(request.body)
        access_token = data.get('access_token')
        refresh_token = data.get('refresh_token')
        csrf_token = data.get('csrf_token')
        
        # Validate access token
        decoded = validate_scute_token(access_token)
        if not decoded:
            return JsonResponse({'error': 'Invalid token'}, status=401)
            
        # Create response with access token validation result
        response = JsonResponse({
            'message': 'Login successful',
            'user': decoded
        })
        
        # Set refresh token in HTTP-only cookie
        TokenManager.set_refresh_token_cookie(response, refresh_token)
        
        return response
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@require_http_methods(["POST"])
def refresh_token(request):
    try:
        # Get refresh token from HTTP-only cookie
        refresh_token = request.COOKIES.get(TokenManager.REFRESH_TOKEN_COOKIE)
        if not refresh_token:
            return JsonResponse({'error': 'No refresh token'}, status=401)
            
        # Use refresh token to get new access token from Scute
        access_token, new_refresh_token = TokenManager.refresh_tokens(refresh_token)
        
        response = JsonResponse({
            'access_token': access_token
        })
        
        # Update refresh token cookie if Scute returned a new one
        if new_refresh_token:
            TokenManager.set_refresh_token_cookie(response, new_refresh_token)
            
        return response
        
    except Exception as e:
        # Clear invalid refresh token
        response = JsonResponse({'error': str(e)}, status=401)
        TokenManager.clear_refresh_token_cookie(response)
        return response

@require_http_methods(["POST"])
def logout(request):
    response = JsonResponse({'message': 'Logged out'})
    TokenManager.clear_refresh_token_cookie(response)
    return response
```

### React Implementation

```typescript
// src/auth/ScuteAuth.tsx

export const ScuteAuthProvider = ({ children }) => {
  const [authState, setAuthState] = useState({
    isAuthenticated: false,
    user: null,
    loading: true,
    accessToken: null
  });

  // Initial authentication
  const login = async (email: string, password: string) => {
    try {
      const { data, error } = await scuteClient.signIn(email, password);
      
      if (error) throw error;

      // Send tokens to backend
      const response = await fetch('/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          access_token: data.session.accessToken,
          refresh_token: data.session.refreshToken,
          csrf_token: data.session.csrfToken
        }),
        credentials: 'include' // Important for cookies
      });

      if (!response.ok) throw new Error('Login failed');

      setAuthState({
        isAuthenticated: true,
        user: data.session.user,
        loading: false,
        accessToken: data.session.accessToken
      });
    } catch (error) {
      console.error('Login error:', error);
      throw error;
    }
  };

  // Token refresh
  const refreshTokens = async () => {
    try {
      const response = await fetch('/auth/refresh', {
        method: 'POST',
        credentials: 'include' // Important for cookies
      });

      if (!response.ok) throw new Error('Refresh failed');

      const data = await response.json();
      
      setAuthState(prev => ({
        ...prev,
        accessToken: data.access_token
      }));

      return data.access_token;
    } catch (error) {
      console.error('Token refresh error:', error);
      throw error;
    }
  };

  // Logout
  const logout = async () => {
    try {
      await fetch('/auth/logout', {
        method: 'POST',
        credentials: 'include'
      });
      
      setAuthState({
        isAuthenticated: false,
        user: null,
        loading: false,
        accessToken: null
      });
    } catch (error) {
      console.error('Logout error:', error);
      throw error;
    }
  };

  // ... rest of the implementation ...
};
```

## Key Points About This Implementation:

1. **HTTP-only Cookie Security:**
   - Refresh token is stored in an HTTP-only cookie
   - Cannot be accessed by JavaScript
   - Only sent over HTTPS
   - SameSite attribute helps prevent CSRF
   - Limited to specific path (/auth/refresh)

2. **Token Flow:**
   - Frontend gets tokens from Scute
   - Sends both tokens to Django backend
   - Backend stores refresh token in HTTP-only cookie
   - Frontend only keeps access token in memory
   - Refresh happens through backend proxy

3. **Security Benefits:**
   - Refresh tokens are not accessible to JavaScript
   - Protected from XSS attacks
   - Proper CSRF protection
   - Backend can implement additional security checks

4. **Implementation Requirements:**
   - HTTPS in production
   - Proper CORS configuration
   - CSRF protection enabled
   - Secure cookie settings
   - Backend proxy for refresh

// ... rest of existing code ... 

### Django Scute Client Implementation

```python
# backend/scute_client.py
import requests
from django.conf import settings

class ScuteClient:
    def __init__(self):
        self.app_id = settings.SCUTE_APP_ID
        self.base_url = settings.SCUTE_API_URL
        
    def refresh_access_token(self, refresh_token: str) -> dict:
        """
        Use refresh token to get a new access token from Scute.
        """
        try:
            response = requests.post(
                f"{self.base_url}/auth/refresh",
                headers={
                    "Content-Type": "application/json",
                    "X-Scute-App-Id": self.app_id
                },
                json={
                    "refresh_token": refresh_token
                }
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to refresh token: {str(e)}")

# views.py
from .scute_client import ScuteClient

class TokenManager:
    # ... existing TokenManager code ...

    @staticmethod
    def refresh_tokens(refresh_token: str) -> tuple[str, str | None]:
        """
        Get new tokens from Scute using refresh token.
        Returns (access_token, new_refresh_token | None)
        """
        scute = ScuteClient()
        result = scute.refresh_access_token(refresh_token)
        
        return (
            result["access_token"],
            result.get("refresh_token")  # May be None if refresh token wasn't rotated
        )

@require_http_methods(["POST"])
def refresh_token(request):
    try:
        # Get refresh token from HTTP-only cookie
        refresh_token = request.COOKIES.get(TokenManager.REFRESH_TOKEN_COOKIE)
        if not refresh_token:
            return JsonResponse({'error': 'No refresh token'}, status=401)
            
        # Use refresh token to get new access token from Scute
        access_token, new_refresh_token = TokenManager.refresh_tokens(refresh_token)
        
        response = JsonResponse({
            'access_token': access_token
        })
        
        # Update refresh token cookie if Scute returned a new one
        if new_refresh_token:
            TokenManager.set_refresh_token_cookie(response, new_refresh_token)
            
        return response
        
    except Exception as e:
        # Clear invalid refresh token
        response = JsonResponse({'error': str(e)}, status=401)
        TokenManager.clear_refresh_token_cookie(response)
        return response

# settings.py
SCUTE_APP_ID = env('SCUTE_APP_ID')
SCUTE_API_URL = env('SCUTE_API_URL', default='https://api.scute.io')
```

