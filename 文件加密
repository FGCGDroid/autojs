"ui";

// ======================================================
//  文件加密/解密工具 v2.4 - 移除时间戳，可正常解密
//  输出目录：/sdcard/加密文件/
// ======================================================

runtime.requestPermissions(["android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE"]);

importClass(javax.crypto.Cipher);
importClass(javax.crypto.spec.SecretKeySpec);
importClass(javax.crypto.spec.IvParameterSpec);
importClass(java.security.SecureRandom);
importClass(java.io.File);
importClass(java.io.FileOutputStream);
importClass(java.lang.System);
importClass(java.io.FileInputStream);
importClass(java.security.MessageDigest);

const MAGIC_HEADER = "A5C8E3";
const IV_SIZE = 16;
const SALT_SIZE = 16;
const OUTPUT_DIR = "/sdcard/加密文件/";

var dir = new File(OUTPUT_DIR);
if (!dir.exists()) dir.mkdirs();

function toSignedByte(v) {
    if (v > 127) v -= 256;
    return v;
}

function encryptData(data, password) {
    var secureRandom = SecureRandom.getInstance("SHA1PRNG");
    var salt = java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE, SALT_SIZE);
    var iv = java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE, IV_SIZE);
    secureRandom.nextBytes(salt);
    secureRandom.nextBytes(iv);

    var uniqueKey = deriveUniqueKey(password, salt);
    var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    var keySpec = new SecretKeySpec(uniqueKey, "AES");
    var ivSpec = new IvParameterSpec(iv);
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
    var encryptedData = cipher.doFinal(data);

    var headerBytes = hexStringToByteArray(MAGIC_HEADER);
    var totalLen = headerBytes.length + salt.length + iv.length + encryptedData.length;
    var result = java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE, totalLen);
    var pos = 0;
    System.arraycopy(headerBytes, 0, result, pos, headerBytes.length);
    pos += headerBytes.length;
    System.arraycopy(salt, 0, result, pos, salt.length);
    pos += salt.length;
    System.arraycopy(iv, 0, result, pos, iv.length);
    pos += iv.length;
    System.arraycopy(encryptedData, 0, result, pos, encryptedData.length);
    return result;
}

function decryptData(data, password) {
    var headerBytes = hexStringToByteArray(MAGIC_HEADER);
    var headerLen = headerBytes.length;
    if (data.length < headerLen + SALT_SIZE + IV_SIZE) throw new Error("数据太短");
    for (var i = 0; i < headerLen; i++) {
        if (data[i] != headerBytes[i]) throw new Error("文件头校验失败");
    }
    var salt = java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE, SALT_SIZE);
    var iv = java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE, IV_SIZE);
    System.arraycopy(data, headerLen, salt, 0, SALT_SIZE);
    System.arraycopy(data, headerLen + SALT_SIZE, iv, 0, IV_SIZE);
    var encryptedLen = data.length - headerLen - SALT_SIZE - IV_SIZE;
    var encryptedData = java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE, encryptedLen);
    System.arraycopy(data, headerLen + SALT_SIZE + IV_SIZE, encryptedData, 0, encryptedLen);

    var uniqueKey = deriveUniqueKey(password, salt);
    var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    var keySpec = new SecretKeySpec(uniqueKey, "AES");
    var ivSpec = new IvParameterSpec(iv);
    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
    return cipher.doFinal(encryptedData);
}

// ---------- 修正：移除时间戳因子 ----------
function deriveUniqueKey(password, salt) {
    var pwdJava = new java.lang.String(password);
    var pwdBytes = pwdJava.getBytes("UTF-8");
    // 反转
    var revBytes = java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE, pwdBytes.length);
    for (var i = 0; i < pwdBytes.length; i++) {
        revBytes[i] = pwdBytes[pwdBytes.length - 1 - i];
    }
    
    // 混合：密码 + 反转密码 + 盐（去掉了时间戳）
    var mixLen = pwdBytes.length + revBytes.length + salt.length;
    var mixed = java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE, mixLen);
    var pos = 0;
    for (var i = 0; i < Math.max(pwdBytes.length, Math.max(revBytes.length, salt.length)); i++) {
        if (i < pwdBytes.length) { mixed[pos] = toSignedByte(pwdBytes[i]); pos++; }
        if (i < revBytes.length) { mixed[pos] = toSignedByte(revBytes[i]); pos++; }
        if (i < salt.length) { mixed[pos] = toSignedByte(salt[i]); pos++; }
    }
    var md = MessageDigest.getInstance("SHA-256");
    var finalKey = md.digest(mixed);
    // 异或扰乱（保持不变）
    for (var i = 0; i < finalKey.length; i++) {
        finalKey[i] = finalKey[i] ^ (i * 3 + 7);
    }
    return finalKey;
}

function hexStringToByteArray(hex) {
    var len = hex.length;
    var data = java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE, len / 2);
    for (var i = 0; i < len; i += 2) {
        var val = parseInt(hex.substring(i, i + 2), 16);
        data[i / 2] = toSignedByte(val);
    }
    return data;
}

function saveBytesToFile(bytes, filePath) {
    var fos = new FileOutputStream(new File(filePath));
    fos.write(bytes);
    fos.flush();
    fos.close();
}

// ==================== 文件浏览器 ====================

function browseFiles(initialPath) {
    if (!initialPath) initialPath = "/sdcard";
    var currentDir = new File(initialPath);
    if (!currentDir.exists()) currentDir = new File("/sdcard");

    var items = [], dirs = [], files = [];
    while (true) {
        var list = currentDir.listFiles();
        if (list == null) {
            toast("无法读取目录");
            return null;
        }
        items = [];
        dirs = [];
        files = [];

        if (currentDir.getParent() != null) {
            items.push("📁 .. (返回上级)");
            dirs.push(currentDir.getParent());
        }

        var fileList = [], dirList = [];
        for (var i = 0; i < list.length; i++) {
            if (list[i].isDirectory()) dirList.push(list[i]);
            else fileList.push(list[i]);
        }
        dirList.sort(function(a, b) { return a.getName().toLowerCase().localeCompare(b.getName().toLowerCase()); });
        fileList.sort(function(a, b) { return a.getName().toLowerCase().localeCompare(b.getName().toLowerCase()); });

        for (var i = 0; i < dirList.length; i++) {
            items.push("📁 " + dirList[i].getName());
            dirs.push(dirList[i].getPath());
        }
        for (var i = 0; i < fileList.length; i++) {
            var size = fileList[i].length();
            var sizeStr = size > 1024*1024 ? (size/(1024*1024)).toFixed(2)+"MB" :
                           size > 1024 ? (size/1024).toFixed(2)+"KB" : size+"B";
            items.push("📄 " + fileList[i].getName() + " (" + sizeStr + ")");
            files.push(fileList[i].getPath());
        }

        var index = dialogs.select("请选择文件（当前路径: " + currentDir.getPath() + "）", items);
        if (index < 0) return null;

        if (index < dirs.length) {
            currentDir = new File(dirs[index]);
            continue;
        } else {
            var filePath = files[index - dirs.length];
            if (filePath) return filePath;
            else { toast("无效选择"); return null; }
        }
    }
}

// ==================== UI ====================

ui.layout(
    <vertical padding="16">
        <text textSize="20sp" textColor="#2196F3" gravity="center" marginBottom="20">🔐 文件加密/解密工具</text>

        <horizontal>
            <text text="文件：" textSize="16sp" layout_weight="1"/>
            <button id="selectBtn" text="浏览文件" style="Widget.AppCompat.Button.Borderless.Colored"/>
        </horizontal>
        <text id="fileInfo" text="未选择任何文件" textSize="14sp" textColor="#666" marginBottom="8"/>
        <input id="filePathInput" hint="或手动输入完整路径" textSize="13sp"/>

        <text text="加密密码：" textSize="16sp" marginTop="12"/>
        <input id="pwdInput" hint="请输入密码（至少6位）" password="true" inputType="textPassword"/>

        <text text="操作类型：" textSize="16sp" marginTop="12"/>
        <radiogroup id="opGroup" orientation="horizontal">
            <radio id="encRadio" checked="true">加密</radio>
            <radio id="decRadio">解密</radio>
        </radiogroup>

        <button id="runBtn" text="开始执行" style="Widget.AppCompat.Button.Colored" marginTop="20"/>
        <text id="statusText" text="准备就绪" textSize="14sp" textColor="#333" gravity="center" marginTop="12"/>
    </vertical>
);

var selectedPath = null;

ui.selectBtn.on("click", function() {
    var startPath = ui.filePathInput.text();
    if (startPath && new File(startPath).exists()) {
        var file = new File(startPath);
        if (file.isFile()) startPath = file.getParent();
    } else {
        startPath = "/sdcard";
    }
    threads.start(function() {
        var path = browseFiles(startPath);
        if (path) {
            ui.run(function() {
                ui.filePathInput.setText(path);
                selectedPath = path;
                var file = new File(path);
                ui.fileInfo.setText("已选择: " + file.getName() + " (大小: " + (file.length() / 1024).toFixed(2) + " KB)");
                toast("已选择: " + file.getName());
            });
        } else {
            toast("未选择文件");
        }
    });
});

ui.filePathInput.on("text_change", function(text) {
    if (text && text.length > 0) {
        var file = new File(text);
        if (file.exists()) {
            ui.fileInfo.setText("手动选择: " + file.getName() + " (大小: " + (file.length() / 1024).toFixed(2) + " KB)");
            selectedPath = text;
        } else {
            ui.fileInfo.setText("手动输入路径（文件不存在）");
        }
    } else {
        ui.fileInfo.setText("未选择任何文件");
        selectedPath = null;
    }
});

ui.runBtn.on("click", function() {
    var pwd = ui.pwdInput.text();
    if (!pwd || pwd.length < 6) {
        toast("密码至少6位");
        return;
    }
    var isEncrypt = ui.encRadio.checked;

    var filePath = selectedPath;
    if (!filePath) {
        var text = ui.filePathInput.text();
        if (text && text.length > 0) {
            var file = new File(text);
            if (file.exists()) filePath = text;
            else {
                toast("文件不存在，请检查路径");
return;
            }
    } else {
            toast("请先选择或输入文件");
            return;
        }
    }

    var file = new File(filePath);
    if (!file.exists()) {
        toast("文件不存在");
        return;
    }

    try {
        var fis = new FileInputStream(file);
        var dataBytes = java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE, file.length());
        fis.read(dataBytes);
        fis.close();
    } catch (e) {
        toast("读取文件失败: " + e.message);
        ui.statusText.setText("读取失败: " + e.message);
        return;
    }

    ui.statusText.setText("⏳ 处理中...");
    threads.start(function() {
        try {
            var resultBytes, outFileName;
            if (isEncrypt) {
                resultBytes = encryptData(dataBytes, pwd);
                outFileName = file.getName() + ".enc";
            } else {
                resultBytes = decryptData(dataBytes, pwd);
                if (file.getName().endsWith(".enc")) {
                    outFileName = file.getName().substring(0, file.getName().length - 4);
                } else {
                    outFileName = file.getName() + ".dec";
                }
            }
            var outPath = OUTPUT_DIR + outFileName;
            saveBytesToFile(resultBytes, outPath);
            ui.run(function() {
                ui.statusText.setText("✅ 完成！\n保存至: " + outPath);
                toast("操作成功！");
            });
        } catch (e) {
            ui.run(function() {
                ui.statusText.setText("❌ 错误: " + e.message);
                toast("操作失败: " + e.message);
            });
            console.error(e);
        }
    });
});

ui.statusText.setText("请选择或输入文件，然后设置密码");