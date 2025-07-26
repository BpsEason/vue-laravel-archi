// frontend-admin/src/stores/auth.js
import { defineStore } from 'pinia';
import { ref } from 'vue';
import axios from 'axios';

export const useAuthStore = defineStore('auth', () => {
    const token = ref(localStorage.getItem('admin_token') || '');
    const user = ref(JSON.parse(localStorage.getItem('admin_user') || 'null'));
    const isRefreshing = ref(false); 
    let failedRequestsQueue = []; 

    const axiosInstance = axios.create({
        baseURL: '/', 
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        },
    });

    axiosInstance.interceptors.request.use(
        config => {
            if (token.value && !config.headers.Authorization) {
                config.headers.Authorization = `Bearer ${token.value}`;
            }
            return config;
        },
        error => Promise.reject(error)
    );

    axiosInstance.interceptors.response.use(
        response => response,
        async error => {
            const originalRequest = error.config;

            if (error.response?.status === 401 && originalRequest.url.indexOf('/refresh') === -1 && !originalRequest._retry) {
                originalRequest._retry = true; 

                if (!isRefreshing.value) {
                    isRefreshing.value = true; 
                    try {
                        const refreshResponse = await axiosInstance.post('/api/admin/refresh'); 
                        token.value = refreshResponse.data.token;
                        localStorage.setItem('admin_token', token.value);

                        failedRequestsQueue.forEach(promise => promise.resolve());
                        failedRequestsQueue = []; 
                        isRefreshing.value = false; 

                        originalRequest.headers['Authorization'] = `Bearer ${token.value}`;
                        return axiosInstance(originalRequest); 
                    } catch (refreshError) {
                        console.error('Token refresh failed:', refreshError.response?.data?.error || refreshError.message);
                        isRefreshing.value = false; 
                        failedRequestsQueue.forEach(promise => promise.reject(refreshError));
                        failedRequestsQueue = [];
                        logout(); // 刷新失敗，登出用戶
                        return Promise.reject(refreshError); 
                    }
                } else {
                    return new Promise((resolve, reject) => {
                        failedRequestsQueue.push({ resolve, reject });
                    })
                    .then(() => {
                        originalRequest.headers['Authorization'] = `Bearer ${token.value}`;
                        return axiosInstance(originalRequest);
                    })
                    .catch(refreshError => {
                        return Promise.reject(refreshError);
                    });
                }
            }
            return Promise.reject(error);
        }
    );

    async function login(credentials) {
        // 實際的登入邏輯，需要替換
        try {
            const response = await axiosInstance.post('/api/admin/login', credentials);
            token.value = response.data.token;
            localStorage.setItem('admin_token', token.value);
            // 假設登入成功後，您可以獲取用戶資訊
            // const userResponse = await axiosInstance.get('/api/admin/user');
            // user.value = userResponse.data;
            // localStorage.setItem('admin_user', JSON.stringify(user.value));
            console.log('Login successful');
            return true;
        } catch (error) {
            console.error('Login failed:', error.response?.data?.error || error.message);
            logout(); // 登入失敗則清除 token
            return false;
        }
    }

    async function fetchUser() {
        // 實際獲取用戶資訊的邏輯，需要替換
        if (!token.value) return null;
        try {
            // const response = await axiosInstance.get('/api/admin/user');
            // user.value = response.data;
            // localStorage.setItem('admin_user', JSON.stringify(user.value));
            // return user.value;
            return { name: "Test User", email: "test@example.com" }; // 佔位數據
        } catch (error) {
            console.error('Fetch user failed:', error.response?.data?.error || error.message);
            logout();
            return null;
        }
    }

    function logout() {
        // 實際的登出邏輯，可能需要發送請求到後端
        axiosInstance.post('/api/admin/logout').catch(e => console.error('Logout API failed:', e));
        token.value = '';
        user.value = null;
        localStorage.removeItem('admin_token');
        localStorage.removeItem('admin_user');
        console.log('Logged out');
        // 可選：重定向到登入頁面
        // router.push('/login');
    }

    return { token, user, login, fetchUser, logout, axiosInstance }; 
});
