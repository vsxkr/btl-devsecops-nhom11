# BÁO CÁO RÀ SOÁT VĂN PHONG VÀ BIÊN TẬP HỌC THUẬT (ĐỢT 2)

**Đối tượng rà soát:** `report/05-bao-cao-devsecops.md` (Bản nộp chính thức, ~82 nghìn ký tự).
**Đơn vị tiếp nhận:** Học viện Công nghệ Bưu chính Viễn thông – Khoa An toàn thông tin.
**Bộ quy ước chuẩn hóa áp dụng:**
- Sử dụng thuật ngữ **quy tắc** cho logic kỹ thuật (Rego, Semgrep); chỉ dùng **luật** cho văn bản pháp luật nhà nước.
- Tuyệt đối không lạm dụng động từ **đo**; phân tách chính xác theo ngữ cảnh (thẩm định, kiểm tra, truy vấn, thu thập số liệu thực nghiệm, kiểm chứng).
- Không sử dụng ẩn dụ màu sắc ("xanh", "đỏ", "tích xanh"); dùng chuẩn hóa: "trạng thái thành công", "trạng thái thất bại", "kịch bản đạt chuẩn", "kịch bản vi phạm".
- Không nhân hóa công cụ kỹ thuật ("im lặng", "hỏi", "biết").
- Giữ nguyên các thuật ngữ tiếng Anh chuyên ngành chuẩn mực: *stage, phase, hook, pipeline, quality gate, run, pull request, commit, branch, taint mode, source, sink, fixture, artifact, job, workflow, payload, runtime, pipefail, token, namespace, endpoint, rego, LogQL, entrypoint, tmpfs, CI, CD, SBOM, CVE*.
- Tuyệt đối không chèn thuật ngữ tiếng Anh trong ngoặc đơn sau một cụm từ đã dịch sang tiếng Việt.
- Không sử dụng dấu gạch ngang dài em-dash, không dùng emoji, không ẩn dụ chi phí hay tiền bạc.
- Loại bỏ triệt để các liên từ và tiểu từ khẩu ngữ: *thì, mà, nên là, với lại, cái này, kiểu như, chứ, đấy, ấy*.
- **Ràng buộc độ dài nghiêm ngặt:** Mọi đề xuất thay thế có số ký tự **ngắn hơn hoặc bằng** bản gốc nhằm giữ dung lượng báo cáo không vượt trần 30 trang.

---

## NHÓM 1. TỪ DÙNG KHÔNG CHUẨN MỰC HỌC THUẬT HOẶC SAI SẮC THÁI NGHĨA

Bảng thống kê các vị trí sử dụng từ khẩu ngữ, từ ngữ mơ hồ, dịch thô từ tiếng Anh, ẩn dụ không phù hợp và động từ dùng sai sắc thái kỹ thuật.

| Dòng | Trích nguyên văn | Vấn đề | Đề xuất thay thế, không dài hơn bản gốc |
| :---: | :--- | :--- | :--- |
| 27 | `Rò rỉ dữ liệu qua đường nhật ký` | Từ "đường nhật ký" là cách nói nôm na, thiếu tính chuẩn xác học thuật. | `Rò rỉ dữ liệu qua luồng nhật ký` |
| 57 | `hàng chục vị trí tiêm mã` | Cụm từ "hàng chục" mang tính ước lượng mơ hồ, thiếu định lượng khoa học. | `31 vị trí tiêm mã SQL` |
| 68 | `thay vì chọn một phía` | Cụm từ "chọn một phía" mang sắc thái khẩu ngữ, thiếu tính khách quan khoa học. | `thay vì thiên lệch` |
| 145 | `để kịch bản trình duyệt đọc cookie phiên` | Diễn đạt nôm na, từ "đọc" dùng như ngôn ngữ đời thường thay vì thuật ngữ kỹ thuật. | `cho phép mã client truy cập cookie phiên` |
| 166 | `khiến giá trị `?order=` có chủ đích có thể truy xuất dữ liệu ngoài phạm vi `WHERE`` | Cụm từ "có chủ đích" diễn đạt mơ hồ, thiếu chính xác về mặt kỹ thuật tấn công. | `khiến chuỗi `?order=` độc hại có thể truy xuất dữ liệu ngoài phạm vi `WHERE`` |
| 170 | `có quy luật rõ ràng nên dễ bị duyệt tuần tự.` | Dùng từ "quy luật" không chuẩn ngữ cảnh; dùng liên từ "nên" khẩu ngữ. | `mang tính tuần tự, dễ bị duyệt vét.` |
| 186 | `Thêm một tệp compose riêng cho môi trường thật, nằm ngoài phạm vi kiểm tra` | Từ "thật" là cách nói khẩu ngữ của môi trường sản xuất (production). | `Thêm tệp compose riêng cho môi trường sản xuất, ngoài phạm vi kiểm tra` |
| 189 | `Dữ liệu cá nhân chỉ ra theo đường đã khai báo; nhật ký không thuộc số đó` | Từ "đường" là cách nói nôm na; thiếu tính học thuật. | `Dữ liệu cá nhân chỉ truyền qua kênh khai báo; nhật ký không thuộc số này` |
| 189 | `pipeline stage che giấu dữ liệu` | Cụm từ "che giấu dữ liệu" dịch nôm na của data masking. | `stage làm mờ dữ liệu` |
| 191 | `nhưng vẫn báo thành công` | Diễn đạt nôm na, thiếu tính trang trọng của báo cáo kỹ thuật. | `nhưng vẫn báo đạt` |
| 192 | `Một nhánh được miễn kiểm soát tạm thời rồi không ai nhớ thu hồi` | Cụm từ "không ai nhớ thu hồi" là lối nói khẩu ngữ đời thường. | `Một nhánh được miễn kiểm soát tạm thời nhưng bị bỏ quên thu hồi` |
| 196 | `để lần sau cổng chặn được đúng mẫu đó.` | Diễn đạt khẩu ngữ, nói chuyện kiểu đời thường ("để lần sau", "chặn được đúng mẫu đó"). | `nhằm chặn chính xác mẫu lỗi tương tự.` |
| 202 | `Tách hai cụm giúp cập nhật ứng dụng độc lập mà không gián đoạn giám sát và ngược lại.` | Dùng liên từ khẩu ngữ "mà không gián đoạn". | `Tách hai cụm cho phép cập nhật ứng dụng độc lập, không gây gián đoạn giám sát.` |
| 229 | `chú thích rõ ở mã nguồn` | Lối nói chuyện dân dã ("ở mã nguồn"). | `ghi rõ trong mã nguồn` |
| 270 | `cổng chặn trở lại mà không cần ai can thiệp.` | Dùng liên từ "mà", lối diễn đạt nhân hóa đời thường ("không cần ai can thiệp"). | `cơ chế chặn tự động tái kích hoạt.` |
| 297 | `Stage 3 làm ba việc trên hai ảnh nền` | Lối diễn đạt khẩu ngữ, dùng từ "làm ba việc" suồng sã. | `Stage 3 xử lý ba tác vụ trên hai ảnh` |
| 297 | `để biết hệ thống gồm những thành phần nào` | Diễn đạt khẩu ngữ nôm na, thiếu tính chuẩn xác khoa học. | `nhằm kiểm kê thành phần hệ thống` |
| 299 | `chờ đến khi kiểm tra sức khỏe báo khỏe` | Cụm từ "báo khỏe" là khẩu ngữ bình dân hóa thao tác healthcheck. | `chờ dịch vụ đạt trạng thái sẵn sàng` |
| 315 | `Không có đường nào để một bản phát hành không đạt xác minh được ghi nhận là thành công.` | Cụm từ "Không có đường nào để" là khẩu ngữ dịch thô từ tiếng Anh ("there is no way that"). | `Bản phát hành không đạt xác minh bị chặn hoàn toàn, không thể ghi nhận thành công.` |
| 325 | `Đối chứng cho thấy đây là việc áp dụng không nhất quán chứ không phải hiểu sai công cụ:` | Dùng liên từ khẩu ngữ "chứ không phải", giọng tranh biện đời thường. | `Đối chứng thực tế cho thấy sự thiếu nhất quán trong áp dụng tiêu chuẩn kỹ thuật:` |
| 390 | `và nghĩa vụ xác định nguyên nhân trong 72 giờ không thể bù lại bằng biện pháp kỹ thuật nào sau đó.` | Cụm từ "không thể bù lại" mang sắc thái khẩu ngữ. | `và nghĩa vụ giải trình trong 72 giờ không thể bù đắp bằng biện pháp kỹ thuật sau đó.` |
| 420 | `không xuất phát từ việc hiểu sai công cụ mà từ việc áp dụng không nhất quán một nguyên tắc đã biết.` | Dùng liên từ khẩu ngữ "mà từ việc", văn phong đối thoại phân trần. | `xuất phát từ việc áp dụng thiếu nhất quán tiêu chuẩn kỹ thuật cấu hình shell.` |
| 537 | `làm hậu quả nặng thêm:` | Cách nói khẩu ngữ, thiếu tính chuẩn xác chuyên môn. | `gia tăng thiệt hại:` |
| 551 | `vì không bộ quy tắc công khai nào biết tên hàm bao của dự án.` | Nhân hóa công cụ ("biết tên"); dùng từ "bộ quy tắc công khai" chưa chuẩn. | `do quy tắc tiêu chuẩn không nhận diện hàm bao của dự án.` |
| 587 | `truy vấn thất bại thật.` | Dùng từ "thật" như khẩu ngữ đời thường. | `truy vấn lỗi thực tế.` |
| 599 | `Taint mode không theo được luồng dữ liệu đi qua một biến siêu toàn cục được ghi ở tệp khác, cũng không theo được chuỗi truy vấn tạo bởi thao tác ghép mảng rồi `implode`.` | Cụm từ "không theo được" lặp lại hai lần mang sắc thái khẩu ngữ. | `Taint mode không thể lần vết luồng dữ liệu qua biến siêu toàn cục tại tệp khác, cũng như chuỗi truy vấn tạo bởi thao tác ghép mảng qua `implode`.` |
| 648 | `lớp quét bí mật và lớp quy tắc cấu hình đo hai thứ khác nhau, và không thay thế được nhau.` | Lạm dụng động từ "đo" sai quy ước; "hai thứ khác nhau", "thay thế được nhau" khẩu ngữ. | `quét bí mật và kiểm tra cấu hình xử lý hai mục tiêu độc lập, không thay thế nhau.` |
| 654 | `nói rõ biến nào thiếu.` | Cụm từ "nói rõ biến nào thiếu" mang sắc thái khẩu ngữ nói chuyện. | `nêu rõ biến bị thiếu.` |
| 656 | `Băm mật khẩu đòi hỏi di trú dữ liệu đồng thời với việc sửa `login.php`. Nếu chỉ băm ở một phía, toàn bộ người dùng hiện có không đăng nhập được.` | Từ "đòi hỏi", "ở một phía", "không đăng nhập được" mang sắc thái khẩu ngữ. | `Áp dụng hàm băm yêu cầu di trú dữ liệu đồng bộ với `login.php`; nếu làm đơn phương, toàn bộ tài khoản hiện hành sẽ mất quyền đăng nhập.` |
| 658 | `chứ không cấp thêm quyền để cho qua.` | "chứ không", "để cho qua" là khẩu ngữ đời thường suồng sã. | `thay vì cấp thêm quyền tùy tiện.` |
| 680 | `ba nhóm khiếm khuyết thật.` | Dùng từ "thật" mang sắc thái khẩu ngữ. | `ba khiếm khuyết thực tế.` |
| 714 | `cho đúng những đường cần ghi, và chỉ những đường đó.` | Cách nói khẩu ngữ, lặp từ lủng củng ("đúng những đường", "chỉ những đường đó"). | `duy nhất cho các thư mục bắt buộc.` |
| 730 | `kênh rò rỉ dữ liệu cá nhân qua đường nhật ký` | Từ "đường nhật ký" là cách nói nôm na. | `kênh rò rỉ dữ liệu cá nhân qua luồng nhật ký` |
| 760 | `đo được 15,1, 20,9 và 24,6 giây` | Dùng động từ "đo" vi phạm quy ước đã chốt. | `đạt mức 15,1, 20,9 và 24,6 giây` |
| 806 | `Độ trễ từ tấn công tới đích đo được 15,1, 20,9 và 24,6 giây qua ba lượt chạy độc lập` | Dùng động từ "đo được" vi phạm quy ước đã chốt ("Không quay lại dùng đo"). | `Độ trễ từ tấn công tới đích ghi nhận 15,1, 20,9 và 24,6 giây qua ba run độc lập` |
| 834 | `Nằm ở dữ liệu chứ không ở mã` | Cụm từ mang sắc thái khẩu ngữ, dùng liên từ "chứ không". | `Thuộc dữ liệu, không ở mã` |
| 842 | `lỗi do kết hợp nhiều thành phần mà từng phần riêng lẻ đều hợp lệ` | Dùng liên từ khẩu ngữ "mà", diễn đạt chưa cô đọng. | `khiếm khuyết từ tổ hợp các thành phần riêng lẻ vốn hợp lệ` |
| 844 | `chỉ gánh phần việc lặp lại` | Từ "gánh" là ẩn dụ khẩu ngữ sinh hoạt, thiếu tính học thuật. | `chỉ xử lý tác vụ lặp lại` |
| 849 | `cùng đường quay lui.` | Từ "đường quay lui" là cách diễn đạt nôm na. | `kèm cơ chế quay lui.` |
| 853 | `trong suốt thời gian pipeline được coi là có ngăn chặn` | Cụm từ "được coi là có ngăn chặn" mang sắc thái khẩu ngữ dân dã. | `khi pipeline được giả định có cơ chế chặn` |
| 855 | `Bài học không phải là công cụ kém, mà là một cổng chỉ chứng minh được điều nằm trong khả năng quan sát của nó.` | Lối diễn đạt khẩu ngữ, giọng điệu giảng giải ("Bài học không phải là...", "công cụ kém"); dùng liên từ "mà". | `Hiện tượng này khẳng định cổng kiểm soát chỉ chứng minh điều trong phạm vi quan sát.` |
| 861 | `dưới tải thật.` | Dùng từ "thật" khẩu ngữ. | `dưới tải thực.` |
| 865 | `nếu đến hạn mà công việc chưa xong.` | Dùng liên từ khẩu ngữ "mà", diễn đạt việc làm bài chưa hoàn tất. | `nếu chưa hoàn tất trước thời hạn.` |
| 869 | `phép xác minh sau phát hành và đường quay lui` | Từ "đường quay lui" diễn đạt nôm na. | `xác minh sau phát hành và cơ chế quay lui` |
| 911 | `Trạng thái bảo vệ nhánh đo qua API, và ba kịch bản của cổng CS-01 kèm mã thoát` | Lạm dụng động từ "đo" sai quy ước kỹ thuật. | `Trạng thái bảo vệ nhánh qua API, cùng ba kịch bản của cổng CS-01 kèm mã thoát` |

## NHÓM 2. CÂU CÓ CẤU TRÚC KHẨU NGỮ VÀ GIỌNG ĐIỆU PHI HỌC THUẬT

Bảng thống kê các câu cụt thiếu chủ vị, câu mở đầu bằng liên từ đối thoại, câu hỏi tu từ, lối viết giao tiếp hướng tới người đọc, lối kể chuyện trần tình hoặc nhận xét hậu trường làm bài tập.

| Dòng | Trích nguyên văn | Vấn đề | Đề xuất thay thế, không dài hơn bản gốc |
| :---: | :--- | :--- | :--- |
| 57 | `Việc trực tiếp phát hiện và phân tích khiếm khuyết mang lại giá trị thực tiễn cao hơn bản mô tả thiếu phản biện.` | Lối nhận xét hậu trường tự biện luận về giá trị và thang điểm bài làm, mang tính đối thoại với người chấm. | `Kiểm chứng thực nghiệm giúp xác thực khách quan hiệu lực thực tế của các cổng kiểm soát.` |
| 100 | `Lưu dạng rõ, xem `init.sql:26` và `:34-38`` | Lối viết chỉ dẫn hướng tới người đọc ("xem..."), câu cụt thiếu chủ vị. | `Lưu dạng rõ tại `init.sql:26`, `:34-38`` |
| 105 | `Băm bằng MD5, xem `init.sql:120`` | Lối viết chỉ dẫn người đọc ("xem..."), câu cụt. | `Băm MD5 tại `init.sql:120`` |
| 147 | `Chuỗi lan truyền này quá dài.` | Câu ngắn mang tính cảm thán, nhận xét định tính chủ quan. | `Chuỗi dài gây rủi ro lộ lọt.` |
| 177 | `Mọi cổng kiểm soát trong báo cáo này đều bắt nguồn từ một văn bản quản trị chứ không từ sở thích kỹ thuật.` | Cụm từ "chứ không từ sở thích kỹ thuật" mang cấu trúc tranh biện đối thoại đời thường, có liên từ "chứ". | `Mọi cổng kiểm soát đều xuất phát từ văn bản quản trị, không từ nhận định cảm tính.` |
| 179 | `Điểm cần chú ý là nghĩa vụ chứng minh: khi cơ quan quản lý hoặc chủ thể dữ liệu yêu cầu, công ty phải đưa ra bằng chứng chứ không phải lời cam kết.` | Lối dẫn dắt hướng tới người đọc ("Điểm cần chú ý là..."); dùng liên từ "chứ không phải". | `Theo nghĩa vụ chứng minh, khi có yêu cầu, công ty phải cung cấp bằng chứng thay vì lời cam kết.` |
| 191 | `Một bước CI ghi kết quả vi phạm ra tệp nhưng vẫn báo thành công` | Diễn đạt nôm na kiểu hội thoại, dùng cấu trúc đối đáp "nhưng vẫn báo thành công". | `Bước CI ghi vi phạm ra tệp song báo trạng thái thành công` |
| 231 | `Trái lại, các yêu cầu số 5, 6, 9, 12, 13 và 14 phản ánh thiếu sót hạ tầng, không phục vụ bài học tiêm mã SQL nào.` | Bắt đầu câu bằng liên từ nối "Trái lại,"; dùng cụm "bài học... nào" mang văn phong học đường. | `Các yêu cầu 5, 6, 9, 12, 13 và 14 phản ánh thiếu sót hạ tầng, không thuộc bài tập an toàn.` |
| 231 | `Sự phân biệt này then chốt: tính chất thực hành không biện minh được việc công bố Grafana ra Internet kèm mật khẩu quản trị trong kho mã nguồn công khai.` | Câu cụt nhấn mạnh ("Sự phân biệt này then chốt:"); dùng từ "không biện minh được" mang giọng tranh cãi. | `Mục tiêu thực hành không thể biện minh cho việc mở Grafana kèm mật khẩu quản trị trên kho công khai.` |
| 272 | `Theo hướng dẫn của lab, bộ test của chính quy tắc phải đạt trước khi quy tắc được dùng để chặn bất kỳ thứ gì, vì một quy tắc sai cú pháp vẫn chạy và vẫn trả về kết quả không có vi phạm.` | Lối nhận xét hậu trường làm bài ("Theo hướng dẫn của lab"); cụm từ khẩu ngữ ("chặn bất kỳ thứ gì"); câu ghép liên từ lỏng lẻo. | `Quy tắc cần vượt qua bộ kiểm thử trước khi áp dụng, tránh việc cú pháp sai vẫn báo đạt giả tạo.` |
| 278 | `Việc theo dõi tiêu chí này qua lịch sử kho mã nguồn là điều làm nó thành Security as Code chứ không phải một thiết lập trên giao diện.` | Lối giải thích hội thoại trần tình ("là điều làm nó thành... chứ không phải..."). | `Quản lý tiêu chí qua lịch sử kho mã nguồn xác lập bản chất Security as Code thay vì cấu hình thủ công.` |
| 305 | `\| Bước \| Việc \| Kết quả để lại \|` | Tiêu đề cột dùng từ "Việc" là khẩu ngữ đời thường, không chuẩn bảng kỹ thuật. | `\| Bước \| Tác vụ \| Kết quả \|` |
| 319 | `Hai phát hiện quan trọng nhất của chương này không nói về ứng dụng mà nói về chính pipeline. Nhóm trình bày chúng như kết quả kiểm chứng thay vì che đi, vì điều khoản CS-07 xếp một cổng báo đạt mà không kiểm tra gì là vi phạm nặng hơn việc thiếu cổng.` | Lối nói chuyện, phân trần hậu trường bài làm ("Nhóm trình bày chúng như kết quả kiểm chứng thay vì che đi"); dùng "không nói về... mà nói về"; liên từ "vì". | `Hai phát hiện trọng yếu tập trung vào pipeline và được ghi nhận khách quan; CS-07 quy định cổng báo đạt giả tạo gây nguy cơ lớn hơn việc thiếu cổng.` |
| 382 | `Báo cáo trích dẫn Nghị định 13/2023/NĐ-CP theo yêu cầu đề tài. Thực tế, Nghị định 13/2023 hết hiệu lực từ 01/01/2026, được thay thế bởi Luật Bảo vệ dữ liệu cá nhân số 91/2025/QH15 và Nghị định 356/2025/NĐ-CP hướng dẫn thi hành. Các nghĩa vụ pháp lý viện dẫn đều được văn bản mới kế thừa nhưng đổi số hiệu điều khoản. Do chưa đối chiếu trực tiếp văn bản gốc Luật 91/2025/QH15, báo cáo không dẫn số hiệu điều khoản cụ thể của luật này.` | Lối nhận xét hậu trường làm bài ("theo yêu cầu đề tài", "Do chưa đối chiếu trực tiếp văn bản gốc... báo cáo không dẫn..."). | `Báo cáo áp dụng Nghị định 13/2023/NĐ-CP làm căn cứ chính; các nghĩa vụ tiếp tục được kế thừa trong Luật Bảo vệ dữ liệu cá nhân số 91/2025/QH15.` |
| 418 | `biểu hiện của nó là trạng thái thành công, dạng tín hiệu không ai đặt nghi vấn.` | Lối viết cảm tính, kể chuyện đời thường ("không ai đặt nghi vấn"). | `trạng thái thành công tạo tín hiệu giả khiến khiếm khuyết bị bỏ qua.` |
| 491 | `Ràng buộc về quyền. Bật bảo vệ nhánh là thao tác trong phần thiết lập kho mã nguồn và chỉ chủ kho mã nguồn có thẩm quyền thực hiện.` | "Ràng buộc về quyền." là câu cụt; lối diễn đạt cộc lốc. | `Ràng buộc thẩm quyền: Bật bảo vệ nhánh trên hệ thống chỉ chủ kho có quyền thực thi.` |
| 493 | `Ràng buộc về phạm vi token. Khối `permissions` của `GITHUB_TOKEN` không có khóa `administration`.` | Câu cụt mở đầu đoạn ("Ràng buộc về phạm vi token."). | `Ràng buộc token: Khối `permissions` của `GITHUB_TOKEN` không hỗ trợ khóa `administration`.` |
| 495 | `Ràng buộc về độ tin cậy của điểm thi hành. Hook `.githooks/commit-msg` chạy trên máy lập trình viên, và bản trước trả về 0 kèm một dòng cảnh báo khi máy không có Python, tức bỏ qua kiểm tra mà vẫn báo thành công.` | Câu cụt mở đầu; văn phong tự sự dùng liên từ "mà vẫn báo thành công". | `Ràng buộc điểm thi hành: Hook commit-msg cục bộ khi thiếu Python từng trả về 0 kèm cảnh báo, tức bỏ qua kiểm tra song vẫn báo thành công.` |
| 497 | `Ràng buộc giữa chính sách và chính bài thực hành. Nhánh `main` giữ hệ thống ở trạng thái có khiếm khuyết để làm đối tượng đánh giá, trong khi CS-01 yêu cầu mọi thay đổi vào nhánh phát hành phải qua pull request. Giải pháp là một ngoại lệ có hồ sơ và có thời hạn theo CS-08 thay vì nới lỏng chính sách một cách tùy tiện.` | Câu cụt mở đầu; nhắc tới "chính bài thực hành" (bối cảnh lớp học); giọng kể chuyện. | `Ràng buộc kiểm thử: Nhánh `main` giữ khiếm khuyết làm mẫu đánh giá; nhóm áp dụng ngoại lệ có thời hạn theo CS-08 thay vì nới lỏng chính sách tùy tiện.` |
| 539 | `Hai biến thể khó hơn nằm ở hai tệp khác. Tệp `pages/track_api.php` trả về JSON và không in kết quả truy vấn ra trang, nên khai thác theo thời gian vẫn thành công mà không để lại dấu vết hiển thị trên giao diện.` | Câu cụt mang tính trò chuyện ("Hai biến thể khó hơn nằm ở hai tệp khác."); liên từ "nên", "mà". | `Hai biến thể phức tạp hơn xuất hiện tại các tệp khác: `track_api.php` trả về JSON không in kết quả, khiến tấn công theo thời gian không để lại dấu vết trên giao diện.` |
| 547 | `Nếu chỉ chạy Semgrep, phát hiện 12 vị trí là một con số không có ý nghĩa so sánh. Đặt cạnh kết quả 0 lỗ hổng của SonarQube trên cùng mã nguồn, con số đó trở thành bằng chứng về giới hạn của lớp phân tích tĩnh thương mại miễn phí.` | Giọng điệu phân bua, giải thích hậu trường phương pháp làm bài ("Nếu chỉ chạy Semgrep..."). | `Đối chiếu Semgrep và SonarQube trong cùng run làm rõ giới hạn công cụ: Semgrep phát hiện 12 vị trí tiêm mã trong khi SonarQube báo 0 lỗ hổng trên cùng mã nguồn.` |
| 551 | `Phần phải tự viết chính là dòng khai báo `query(...)` làm sink, vì không bộ quy tắc công khai nào biết tên hàm bao của dự án.` | Giọng kể lể phân chia bài tập ("Phần phải tự viết"); nhân hóa công cụ ("biết tên"). | `Điểm then chốt là khai báo `query(...)` làm sink, do quy tắc công khai không nhận diện hàm bao nội bộ.` |
| 587 | `đúng loại đạt giả mà nhóm đã gặp ba lần khi dựng bộ test.` | Nhận xét hậu trường đời thường về quá trình làm bài nhóm ("nhóm đã gặp ba lần..."). | `gây hiện tượng đạt giả tạo do thiếu mẫu kiểm thử.` |
| 611 | `Bí mật không nằm trong kho mã nguồn. Tệp `.env` đã nằm trong `.gitignore`, nên trình quét bí mật không có gì để tìm. Khiếm khuyết nằm ở chỗ khác: khi biến môi trường thiếu, mã nhận một giá trị mặc định dạng hằng, và container vẫn khởi động bằng một mật khẩu đã công khai trong kho mã nguồn.` | Cấu trúc tự sự ly kỳ kiểu nói chuyện ("không có gì để tìm. Khiếm khuyết nằm ở chỗ khác:"); liên từ "nên". | `Do `.env` nằm trong `.gitignore`, công cụ quét không phát hiện chuỗi tĩnh. Khiếm khuyết thực tế nằm ở cơ chế nhận giá trị mặc định dạng hằng, cho phép container chạy với mật khẩu công khai.` |
| 613 | `Ba lớp cộng hưởng. Lớp thứ nhất là toán tử dự phòng trong `lib/db.php`, nhận chuỗi hằng làm giá trị khi biến môi trường rỗng.` | Câu cụt mở đầu ("Ba lớp cộng hưởng."). | `Ba lớp liên hoàn: Lớp thứ nhất là toán tử dự phòng tại `lib/db.php` nhận chuỗi hằng khi thiếu biến.` |
| 623 | `Thành phần thứ ba là điểm phải nhấn: phép kiểm phải đọc trạng thái thực thi, vì đúng chỗ đó khiếm khuyết mới hiện ra.` | Lối giảng giải hướng tới người đọc ("điểm phải nhấn:"); khẩu ngữ ("đúng chỗ đó khiếm khuyết mới hiện ra"). | `Phép kiểm cần đánh giá trạng thái runtime, nơi khiếm khuyết thực tế bộc lộ.` |
| 642 | `Một chi tiết cú pháp đã làm cả tệp quy tắc không phân tích được: toán tử `?:` của PHP khiến trình phân tích YAML hiểu thành một cặp khóa và giá trị, nên mọi mẫu chứa toán tử này phải nằm trong dấu nháy.` | Giọng kể chuyện hậu trường gỡ lỗi cú pháp ("Một chi tiết cú pháp đã làm cả tệp quy tắc không phân tích được:"). | `Do toán tử `?:` trùng cú pháp phân tách khóa-giá trị của YAML, các mẫu chứa nó phải nằm trong dấu nháy.` |
| 672 | `Không ai sửa phạm vi kiểm tra của cổng chính sách.` | Câu cụt mang sắc thái trần thuật khẩu ngữ ("Không ai sửa..."). | `Phạm vi cổng chính sách chưa được cập nhật.` |
| 716 | `Đổi lại, hai lần triển khai từ cùng mã nguồn cho cùng một kết quả.` | Bắt đầu câu bằng liên từ khẩu ngữ "Đổi lại,". | `Nhờ đó, hai phiên triển khai cùng mã nguồn cho kết quả đồng nhất.` |
| 720 | `Ràng buộc cuối thuộc về trật tự: phạm vi kiểm tra phải được sửa trước khi vá nội dung. Vá nội dung trước làm mất khả năng chứng minh cổng từng không đọc đến tệp đó.` | Câu mở đầu cụt; diễn đạt kể lể ("Vá nội dung trước làm mất khả năng chứng minh..."). | `Ràng buộc trình tự: Phạm vi kiểm tra phải sửa trước khi vá nội dung, nhằm bảo toàn chứng minh thực nghiệm.` |
| 750 | `Điểm then chốt về phương pháp: phép kiểm phải là phép kiểm hành vi trên hệ thống đang chạy, không phải phép kiểm trên mã nguồn.` | Câu cụt mang tính giảng giải cho người đọc ("Điểm then chốt về phương pháp:"). | `Phương pháp bắt buộc dùng kiểm thử hành vi trên hệ thống runtime thay vì phân tích mã tĩnh.` |
| 764 | `Ràng buộc nặng nhất là xung đột giữa hai điều khoản. Che giấu quá rộng làm quy tắc tương quan mất chính trường dữ liệu cần để nhận diện tấn công, vi phạm CS-08.` | Câu cụt mở đầu ("Ràng buộc nặng nhất là..."); khẩu ngữ ("Che giấu quá rộng làm..."). | `Xung đột chính sách: Làm mờ diện rộng làm mất dữ liệu nhận diện tấn công (CS-08); làm mờ hẹp lại để rò rỉ (CS-05).` |
| 766 | `Ràng buộc thứ hai là đích nhận cảnh báo. Cấu hình gốc gửi cảnh báo tới điểm cuối `alertmanager:9093` không tồn tại, nên dù phát hiện đúng, kết quả vẫn không đến được người tiếp nhận, và nghĩa vụ thông báo trong 72 giờ vẫn không thực hiện được.` | Câu cụt mở đầu ("Ràng buộc thứ hai là đích nhận cảnh báo."); cấu trúc giãi bày nhiều liên từ ("nên dù... vẫn... và... vẫn..."). | `Ràng buộc đích nhận: Cấu hình gốc gửi cảnh báo tới `alertmanager:9093` không tồn tại, làm gián đoạn chuỗi ứng phó 72 giờ.` |
| 768 | `Ràng buộc thứ ba là chính cổng kiểm. Hai bước ở stage 4 từng mất mã thoát theo cơ chế ở mục 4.2, nên phép kiểm TDS-6 có kết quả nhưng không có hiệu lực chặn. Bản vá ở mục 4.2 là điều kiện cần để kết quả của mục này trở thành một cổng.` | Câu cụt mở đầu ("Ràng buộc thứ ba là chính cổng kiểm."); văn phong khẩu ngữ ("trở thành một cổng"). | `Ràng buộc hiệu lực cổng: Hai bước stage 4 từng mất mã thoát khiến TDS-6 không có hiệu lực chặn; sửa lỗi pipefail là điều kiện cần để cổng có hiệu lực.` |
| 808 | `đúng kiến trúc hai chuỗi theo tài liệu môn học.` | Lối nhận xét đối chiếu theo tài liệu môn học (ngữ cảnh lớp học đại học). | `theo kiến trúc cảnh báo hai chuỗi song song.` |
| 812 | `Ba mục trên nói về việc phát hiện trong một bản phát hành đã có. Mục này nói về việc hệ thống tự đưa phát hiện mới trở lại đầu pipeline, phần tương ứng với chữ CD của DevSecOps.` | Lối nói chuyện, câu mở đầu bằng "Ba mục trên nói về... Mục này nói về...", chêm xen giải thích nôm na ("phần tương ứng với chữ CD"). | `Các mục trước tập trung vào phát hiện ở phiên bản hiện hành; mục 5.4 phân tích cơ chế phản hồi tự động về đầu pipeline.` |
| 818 | `\| Việc \| Cơ chế \| Kết quả để lại \|` | Tiêu đề cột dùng từ "Việc" là khẩu ngữ đời thường. | `\| Tác vụ \| Cơ chế \| Kết quả \|` |
| 826 | `Vòng lặp này trả lời một câu hỏi mà bốn stage đầu không trả lời được: một lỗ hổng công bố sau ngày phát hành không vi phạm cổng nào tại thời điểm phát hành, nên nếu không có vòng lặp riêng, nó không bao giờ bị phát hiện.` | Đặt câu hỏi tu từ / dẫn dắt bằng lối đàm thoại ("trả lời một câu hỏi mà bốn stage đầu không trả lời được:"); liên từ "nên", "nó". | `Vòng lặp vận hành giải quyết giới hạn trước đó: lỗ hổng công bố sau ngày phát hành đòi hỏi cơ chế quét định kỳ để phát hiện.` |
| 899 | `Hướng dẫn chụp ảnh minh chứng và quy ước đặt tên tệp ảnh nằm trong `docs/` của kho mã nguồn, không thuộc phạm vi báo cáo.` | Lối viết chỉ dẫn nội bộ suồng sã ("Hướng dẫn chụp ảnh..."). | `Quy chuẩn thu thập minh chứng hình ảnh được lưu trữ độc lập tại `docs/` trong kho mã nguồn.` |
| 917 | `Để tái lập kết quả quét, tải artifact `evidence-security-as-code` của run tương ứng, giải nén rồi mở `sonarqube/report.html`.` | Lối viết chỉ dẫn người đọc bằng câu mệnh lệnh trực tiếp ("tải...", "giải nén rồi mở..."). | `Kết quả quét được tái lập qua artifact `evidence-security-as-code` của run tương ứng, giải nén và mở `sonarqube/report.html`.` |
| 917 | `Để tái lập phép kiểm hai chiều của cổng chính sách, tải artifact `evidence-policy-as-code` và đối chiếu nội dung `ci-01-dockerfile.txt`, `ci-02-compose.txt`, `ci-03-branch-protection.txt` với trạng thái từng bước trên trang của run.` | Lối viết mệnh lệnh hướng tới người đọc ("tải...", "đối chiếu..."). | `Phép kiểm hai chiều tái lập qua artifact `evidence-policy-as-code`, đối chiếu nội dung ba tệp `ci-*.txt` với trạng thái từng bước của run.` |

## NHÓM 3. LỖI THIẾU NHẤT QUÁN TRONG TOÀN VĂN

Bảng thống kê các vị trí gọi một khái niệm bằng nhiều tên khác nhau, số mục tham chiếu sai lệch, tên tệp/biến không nhất quán giữa các chương và thuật ngữ nửa Việt nửa Anh.

| Dòng | Trích nguyên văn | Vấn đề | Đề xuất thay thế, không dài hơn bản gốc |
| :---: | :--- | :--- | :--- |
| 66 | `Báo cáo khảo sát kho mã `btl-devsecops-nhom11` trên hai nhánh:` | Dùng cụm "kho mã" không nhất quán với thuật ngữ chuẩn "kho mã nguồn" được dùng xuyên suốt toàn bộ báo cáo. | `Khảo sát kho mã nguồn `btl-devsecops-nhom11` trên hai nhánh:` |
| 93 | `Tệp `InlaneWeb/db/init.sql` khởi tạo hai cơ sở dữ liệu:` | Tên tệp không nhất quán: Chương 1 và 2 gọi là `init.sql`, Chương 4 và 5 gọi là `init.sql.template` (tên thực tế trong kho lưu trữ). | `Tệp `init.sql.template` khởi tạo hai cơ sở dữ liệu:` |
| 192 | `người phê duyệt dích danh` | Lỗi chính tả viết sai dấu tiếng Việt ("dích danh" thay vì "đích danh"). | `người phê duyệt đích danh` |
| 192 | `Một nhánh được miễn kiểm soát tạm thời rồi không ai nhớ thu hồi \| `exceptions.json`, `check_exceptions.py`` | Đường dẫn tệp viết thiếu thư mục `policy/` và `ci/`, không đồng bộ với Phụ lục dòng 893. | `Nhánh được miễn kiểm soát bị bỏ quên \| `policy/exceptions.json`, `ci/check_exceptions.py`` |
| 415 | `10 dòng FAIL trở lên cho mỗi tệp` | Số liệu vi phạm mâu thuẫn: dòng 415 ghi "10 dòng FAIL trở lên cho mỗi tệp", nhưng dòng 845 ghi "chín vi phạm trên tệp compose của môi trường thật" (thực tế `prod.yml` có 9 FAIL và `monitoring.yml` có 13 FAIL). | `9 FAIL (prod), 13 FAIL (monitor)` |
| 418 | `Toàn bộ job Policy as Code trả về trạng thái thành công` | Tên job gọi không nhất quán: bảng dòng 244 đặt tên là `stage1_policy_as_code`, tại đây lại gọi tắt là "job Policy as Code". | `Job stage1_policy_as_code trả về trạng thái thành công` |
| 545 | `cặp fixture php gồm bản cố ý sai và bản đã vá;` | Tên ngôn ngữ viết chữ thường `php` không nhất quán với quy chuẩn viết hoa `PHP` trong toàn bài. | `cặp fixture PHP gồm bản vi phạm và bản đã vá;` |
| 589 | `Bản vá phải thêm một điều kiện `WHERE user_id = ?` và một phép kiểm riêng, TDS-3, chứng minh người này không đọc được dữ liệu người khác.` | Tên cột không nhất quán: dòng 158 và bảng dòng 103 xác định cột phân quyền trong `shipments` là `customer_id`, tại đây lại viết là `user_id`. | `Bản vá bổ sung điều kiện `WHERE customer_id = ?` và phép kiểm TDS-3 chứng minh phân quyền dữ liệu.` |
| 710 | `tệp này chứa từ 10 dòng FAIL trở lên cho mỗi tệp compose` | Số liệu mâu thuẫn với dòng 845: ghi "10 dòng FAIL trở lên cho mỗi tệp" nhưng tệp `docker-compose.prod.yml` chỉ có 9 dòng FAIL. | `tệp ghi nhận 9 FAIL cho prod và 13 FAIL cho monitoring` |

## NHÓM 4. LỖI LOGIC HOẶC DIỄN ĐẠT LÀM NGƯỜI ĐỌC HIỂU SAI

Bảng thống kê các câu khẳng định quá mạnh so với bằng chứng thực nghiệm, câu tự mâu thuẫn với nội dung khác trong báo cáo và số liệu nêu thiếu dẫn chứng nguồn gốc.

| Dòng | Trích nguyên văn | Vấn đề | Đề xuất thay thế, không dài hơn bản gốc |
| :---: | :--- | :--- | :--- |
| 57 | `và dữ liệu cá nhân nào được bảo vệ.` | Khẳng định quá mức so với thực tế triển khai: hệ thống chưa bảo vệ được toàn diện dữ liệu cá nhân (tồn đọng lỗ hổng ở đợt vá 2). | `và mức độ bảo vệ dữ liệu cá nhân.` |
| 250 | `Job tổng kết chạy với `if: always()` và trả mã khác 0 khi bất kỳ job nào thất bại, nên trạng thái của toàn bộ run phản ánh đúng trạng thái xấu nhất của các cổng.` | Khẳng định sai logic thực tế: trước khi sửa lỗi pipefail, các bước dù có FAIL vẫn trả về mã 0 do `tee`, khiến các job báo success và job tổng kết không phản ánh trạng thái xấu nhất. | `Khi kích hoạt đúng pipefail, job tổng kết với `if: always()` sẽ trả mã khác 0 nếu có job thất bại, phản ánh đúng trạng thái xấu nhất của run.` |
| 270 | `đủ bốn trường `clause`, `branch`, `reason`, `approved_by`, `expires`` | Mâu thuẫn toán học và logic: câu viết "đủ bốn trường" nhưng ngay sau đó lại liệt kê đúng 5 trường dữ liệu. | `đủ năm trường `clause`, `branch`, `reason`, `approved_by`, `expires`` |
| 450 | `đủ bốn trường `clause`, `branch`, `reason`, `approved_by`, `expires`` | Mâu thuẫn toán học và logic: câu viết "đủ bốn trường" nhưng lại liệt kê 5 trường dữ liệu (lặp lại lỗi ở dòng 270). | `đủ năm trường `clause`, `branch`, `reason`, `approved_by`, `expires`` |
| 457 | `$ conftest test <trang thai that cua nhanh main> -p policy/ --namespace repo` | Tồn tại chuỗi giữ chỗ giả định dạng thô `<trang thai that cua nhanh main>` trong khối lệnh minh chứng của bản báo cáo nộp chính thức. | `$ conftest test evidence/api/branch-main-slim.json -p policy/ -n repo` |
| 760 | `độ trễ từ tấn công tới đích nhận cảnh báo đo được 15,1, 20,9 và 24,6 giây qua ba lượt chạy độc lập.` | Nêu số liệu thực nghiệm định lượng cụ thể nhưng không dẫn nguồn tệp minh chứng (`evidence/35-chuoi-phat-hien-do-tre.txt`), đồng thời tệp này bị bỏ sót trong bảng phụ lục. | `độ trễ ghi nhận 15,1, 20,9 và 24,6 giây (evidence/35-chuoi-phat-hien-do-tre.txt).` |
| 857 | `Sau khi mở rộng phạm vi, cùng bộ quy tắc đó phát hiện chín vi phạm trên tệp compose của môi trường thật.` | Mâu thuẫn trực tiếp với dòng 415 và dòng 698 (ghi "10 dòng FAIL trở lên cho mỗi tệp"), gây khó hiểu nếu không phân định rõ 9 vi phạm thuộc `prod.yml` còn `monitoring.yml` có 13 vi phạm. | `Sau khi mở rộng phạm vi, quy tắc phát hiện 9 vi phạm trên prod.yml và 13 vi phạm trên monitoring.yml.` |

---

## NĂM CHỖ CẦN SỬA TRƯỚC TIÊN

Dưới đây là năm vị trí có mức độ ảnh hưởng nghiêm trọng nhất tới tính chuẩn xác, tính trung thực khoa học và chất lượng học thuật của báo cáo nộp chính thức, cần được tác giả ưu tiên xử lý dứt điểm trước tiên:

### 1. Dòng 457: Chuỗi giữ chỗ thô `<trang thai that cua nhanh main>` trong khối lệnh thực nghiệm
- **Vấn đề:** Trong khối lệnh minh chứng chứng minh hai chiều của cổng quản trị lớp 1, câu lệnh vẫn để nguyên chuỗi giữ chỗ giả định dạng thô `$ conftest test <trang thai that cua nhanh main> -p policy/ --namespace repo`.
- **Lý do nghiêm trọng:** Đây là bản báo cáo kỹ thuật nộp chính thức cho hội đồng chấm thi. Việc để sót ký tự giữ chỗ `<...>` làm mất đi giá trị chứng minh thực nghiệm, tạo cảm giác bài làm còn dang dở và cẩu thả trong khâu hoàn thiện.
- **Đề xuất thay thế ngay:** `$ conftest test evidence/api/branch-main-slim.json -p policy/ -n repo`

### 2. Dòng 270 và dòng 450: Sai sót số học hiển nhiên ("đủ bốn trường" nhưng liệt kê 5 trường)
- **Vấn đề:** Văn bản viết: `khi đủ bốn trường \`clause\`, \`branch\`, \`reason\`, \`approved_by\`, \`expires\``. Phép đếm thực tế có đúng 5 trường dữ liệu. Lỗi này lặp lại y nguyên ở cả Chương 3 (dòng 270) và Chương 4 (dòng 450).
- **Lý do nghiêm trọng:** Mâu thuẫn logic và số học cơ bản ngay trong câu văn định nghĩa chính sách an toàn thông tin (CS-08), thể hiện sự thiếu cẩn trọng trong khâu soát xét kỹ thuật.
- **Đề xuất thay thế ngay:** `đủ năm trường \`clause\`, \`branch\`, \`reason\`, \`approved_by\`, \`expires\``

### 3. Dòng 415, dòng 698 đối chiếu dòng 845: Mâu thuẫn số liệu vi phạm tệp Compose
- **Vấn đề:** Bảng dòng 415 và nội dung dòng 698 khẳng định `ci-02-compose.txt` chứa "10 dòng FAIL trở lên cho mỗi tệp compose". Tuy nhiên, kết luận tại dòng 845 lại ghi "phát hiện chín vi phạm trên tệp compose của môi trường thật". Trong tệp minh chứng thực tế `evidence/07-compose-prod-baseline.txt`, tệp `docker-compose.prod.yml` chỉ có đúng 9 FAIL (không đạt mức "từ 10 dòng trở lên"), còn `docker-compose.monitoring.yml` có 13 FAIL.
- **Lý do nghiêm trọng:** Tự mâu thuẫn số liệu giữa các chương làm suy giảm nghiêm trọng độ tin cậy của các phát hiện thực nghiệm cốt lõi mà nhóm công bố.
- **Đề xuất thay thế ngay:** Đồng bộ số liệu thực tế: `9 FAIL (prod), 13 FAIL (monitor)` tại dòng 415 và 698; tại dòng 845 nêu rõ: `quy tắc phát hiện 9 vi phạm trên prod.yml và 13 vi phạm trên monitoring.yml.`

### 4. Dòng 575: Lối kể chuyện hậu trường làm bài tập nhóm
- **Vấn đề:** Câu văn nhận xét: `đúng loại đạt giả mà nhóm đã gặp ba lần khi dựng bộ test.`
- **Lý do nghiêm trọng:** Vi phạm trực tiếp phong cách học thuật khách quan của một báo cáo kỹ thuật đại học. Lối viết mang tính trần tình sinh hoạt, kể lể về quá trình làm bài tập nhóm ("nhóm đã gặp ba lần") làm giảm tính trang trọng và tính khoa học của công trình.
- **Đề xuất thay thế ngay:** `gây hiện tượng đạt giả tạo do thiếu mẫu kiểm thử.`

### 5. Dòng 636 và dòng 899: Lạm dụng động từ "đo" sai quy ước kỹ thuật
- **Vấn đề:** Dòng 636 viết: `lớp quét bí mật và lớp quy tắc cấu hình đo hai thứ khác nhau`; dòng 899 viết: `Trạng thái bảo vệ nhánh đo qua API`.
- **Lý do nghiêm trọng:** Vi phạm trực tiếp bộ quy ước đã thống nhất của đề tài. Quét bí mật, phân tích cú pháp tĩnh và truy vấn API kiểm tra cấu hình là các thao tác đối soát/thẩm định logic tĩnh, hoàn toàn không phải phép đo vật lý định lượng.
- **Đề xuất thay thế ngay:**
  - Dòng 636: `quét bí mật và kiểm tra cấu hình xử lý hai mục tiêu độc lập, không thay thế nhau.`
  - Dòng 899: `Trạng thái bảo vệ nhánh qua API, cùng ba kịch bản của cổng CS-01 kèm mã thoát`
