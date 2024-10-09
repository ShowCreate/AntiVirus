#include <windows.h>
#include <stdio.h>

// 창 프로시저 (WindowProcedure)
LRESULT CALLBACK WindowProcedure(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        // 화면에 출력할 텍스트 (멀티바이트 문자열)
        const char* text = "This is a message in Korean.";

        // 텍스트 크기 측정 (멀티바이트 버전 함수 사용)
        SIZE textSize;
        GetTextExtentPoint32A(hdc, text, strlen(text), &textSize);

        // 창 크기 가져오기
        RECT clientRect;
        GetClientRect(hwnd, &clientRect);

        // 텍스트를 중앙에 맞추기 위한 좌표 계산
        int x = (clientRect.right - textSize.cx) / 2;  // 가로 중앙
        int y = (clientRect.bottom - textSize.cy) / 2; // 세로 중앙

        // 텍스트 출력 (멀티바이트 버전 함수 사용)
        TextOutA(hdc, x, y, text, strlen(text));

        EndPaint(hwnd, &ps);
        break;
    }
    case WM_CLOSE:
        DestroyWindow(hwnd);
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, message, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    // 콘솔 창 출력 (멀티바이트 문자열 사용)
    printf("Creating a window...\n");

    // 윈도우 클래스 설정
    WNDCLASSA wc = { 0 };
    wc.lpfnWndProc = WindowProcedure; // 창 프로시저 연결
    wc.hInstance = hInstance;
    wc.lpszClassName = "MyWindowClass";  // 멀티바이트 문자열 사용
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);  // 기본 화살표 커서 사용
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1); // 창 배경 설정

    // 윈도우 클래스 등록 (멀티바이트 버전 사용)
    if (!RegisterClassA(&wc)) {  // 멀티바이트 버전 사용
        MessageBoxA(NULL, "Window class registration failed!", "Error", MB_ICONEXCLAMATION | MB_OK);  // 멀티바이트 버전 사용
        return 1;
    }

    // 화면 해상도 얻기
    int screenWidth = GetSystemMetrics(SM_CXSCREEN); // 화면의 가로 길이
    int screenHeight = GetSystemMetrics(SM_CYSCREEN); // 화면의 세로 길이

    // 창 크기 설정
    int windowWidth = 400;
    int windowHeight = 200;

    // 창을 화면의 가운데에 배치
    int posX = (screenWidth - windowWidth) / 2; // 가로 중앙 좌표
    int posY = (screenHeight - windowHeight) / 2; // 세로 중앙 좌표

    // 윈도우 창 생성 (멀티바이트 버전 사용)
    HWND hwnd = CreateWindowExA(0, "MyWindowClass", "Korean Alert Box", WS_OVERLAPPEDWINDOW,  // 멀티바이트 버전 사용
        posX, posY, windowWidth, windowHeight, NULL, NULL, hInstance, NULL);

    if (hwnd == NULL) {
        MessageBoxA(NULL, "Window creation failed!", "Error", MB_ICONEXCLAMATION | MB_OK);  // 멀티바이트 버전 사용
        return 1;
    }

    // 창 표시 및 업데이트
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    // 메시지 루프
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}