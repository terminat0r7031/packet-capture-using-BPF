CHỈ CHẠY TRÊN LINUX, KHÔNG CHẠY ĐƯỢC TRÊN WINDOWS

# hướng dẫn biên dịch:
gcc simpleCapture.cpp -o simpleCapture -lstdc++

# hướng dẫn chạy:
    - Chạy file thực thi với quyền root. Ví dụ: sudo ./simpleCapture
    - Hiển thị menu hướng dẫn: sudo ./simpleCapture
    - Hiển thị danh sách các card mạng: sudo ./simpleCapture -l
    - Bắt gói tin trên card wlan0, xuất dữ liệu ra file text, đọc luật từ file luat.txt : 
        sudo ./simpleCapture -i wlan0 -o out.txt -t 0 -e luat.txt 

# mẫu nội dung file luật (Chỉ viết luật trên 1 dòng):
để bắt các gói tin có địa chỉ ip 113.171.23.11: ipsrc == 113.171.23.11 || ipdst == 113.171.23.11