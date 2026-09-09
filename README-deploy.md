# App tra cứu đất đai + đăng nhập/phân quyền (Cloudflare Pages + D1)

Cổng đăng nhập: phải đăng nhập mới vào được app. Admin (tài khoản đầu tiên)
tạo/xóa user, đổi mật khẩu, cấp quyền admin. Mật khẩu lưu dạng băm PBKDF2.

## Thành phần
- index.html ............ app tra cứu (được cổng đăng nhập bảo vệ)
- login.html ............ trang đăng nhập / tạo admin lần đầu
- admin.html ............ trang quản trị người dùng (chỉ admin)
- mot-coi-di-ve.ogg ..... nhạc nút Giải trí
- functions/ ............ backend (Pages Functions): đăng nhập, phiên, quản lý user
- schema.sql ............ bảng users + sessions cho D1
- wrangler.toml ......... khai báo project + ràng buộc D1 (binding tên "DB")

## Cài đặt (dùng Wrangler — khuyên dùng)
Cần Node.js. Mở terminal trong thư mục này:

1) Đăng nhập Cloudflare:
   npx wrangler login

2) Tạo database D1:
   npx wrangler d1 create tra-cuu-dat-dai-db
   -> in ra "database_id = ...". COPY id đó dán vào wrangler.toml (thay DÁN_DATABASE_ID_VÀO_ĐÂY).

3) Tạo bảng trong D1 (chạy trên bản remote):
   npx wrangler d1 execute tra-cuu-dat-dai-db --remote --file=schema.sql

4) Deploy lên đúng project đang chạy:
   npx wrangler pages deploy . --project-name=tra-cuu-dat-dai

5) Gắn D1 vào Pages (nếu bước 4 chưa tự gắn):
   Dashboard -> Workers & Pages -> tra-cuu-dat-dai -> Settings -> Functions
   -> D1 database bindings -> Add: Variable name = DB, chọn database tra-cuu-dat-dai-db
   -> Save, rồi deploy lại (bước 4).

## Cách dùng lần đầu
- Mở https://tra-cuu-dat-dai.pages.dev/  -> tự chuyển sang /login.html.
- Lần đầu (chưa có ai) trang hiện "Tạo tài khoản admin": đặt username + mật khẩu -> đó là ADMIN của bạn.
- Đăng nhập xong vào thẳng app. Góc trên phải có tên bạn + "⚙ Quản trị" + "Đăng xuất".
- Vào ⚙ Quản trị để thêm user cho người khác (đặt username + mật khẩu, tùy chọn cấp quyền admin).
- Người bạn tạo dùng chính username/mật khẩu đó để đăng nhập.

## Ghi chú
- Binding D1 BẮT BUỘC tên "DB" (code dùng env.DB).
- Mọi đường dẫn (app, nhạc, admin) đều bị chặn nếu chưa đăng nhập; chỉ /login.html mở công khai.
- Đổi/xóa admin: tạo thêm 1 admin khác trước, không tự xóa chính mình.
- Muốn cập nhật nội dung app (edges mới): thay index.html rồi deploy lại (bước 4). KHÔNG cần đụng D1.
- Phiên đăng nhập 7 ngày; đăng xuất để xóa phiên.
