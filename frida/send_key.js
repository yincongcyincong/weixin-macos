// pure_js_keyboard_injector.js
console.log("Pure JS Keyboard Injector - Starting...");

// 常量定义
const NSEventTypeKeyDown = 10;
const NSEventTypeKeyUp = 11;
const kVK_Return = 36;  // 回车键

// 1. Hook QNSView的handleKeyEvent方法
if (ObjC.available) {
    const QNSView = ObjC.classes.QNSView;

    if (QNSView) {
        console.log("✓ Found QNSView class");

        // Hook方法
        const handleKeyEventMethod = QNSView['- handleKeyEvent:eventType:'];
        if (handleKeyEventMethod) {
            Interceptor.attach(handleKeyEventMethod.implementation, {
                onEnter: function(args) {
                    console.log("\n[QNSView Hook]");
                    const event = new ObjC.Object(args[2]);
                    const eventType = args[3];
                    console.log(`Event Type (a4): ${eventType}`);
                    console.log(`KeyCode: ${event.keyCode()}`);
                    console.log(`Characters: ${event.characters()}`);
                }
            });
            console.log("✓ QNSView handleKeyEvent hooked");
        }
    }
}

// 2. 发送回车键的函数
function sendEnterKey() {
    try {
        console.log("\n=== 发送回车键 ===");

        const NSApplication = ObjC.classes.NSApplication;
        const NSEvent = ObjC.classes.NSEvent;
        const app = NSApplication.sharedApplication();
        const keyWindow = app.keyWindow();

        if (!keyWindow) {
            console.log("❌ 没有找到活动窗口");
            return;
        }

        console.log(`窗口: ${keyWindow}`);

        // 查找QNSView
        function findQNSView(view) {
            if (view.$className === 'QNSView') {
                return view;
            }

            try {
                const subviews = view.subviews();
                const count = subviews.count();
                for (let i = 0; i < count; i++) {
                    const subview = subviews.objectAtIndex_(i);
                    const found = findQNSView(subview);
                    if (found) return found;
                }
            } catch (e) {
                // 忽略错误
            }
            return null;
        }

        const contentView = keyWindow.contentView();
        const qnsView = findQNSView(contentView);

        if (!qnsView) {
            console.log("❌ 没有找到QNSView，使用备用方法");
            sendEnterKeyAlternative();
            return;
        }

        console.log(`✓ 找到QNSView: ${qnsView}`);

        // 创建回车键按下事件
        const keyDownEvent = NSEvent.keyEventWithType_location_modifierFlags_timestamp_windowNumber_context_characters_charactersIgnoringModifiers_isARepeat_keyCode_(
            NSEventTypeKeyDown,  // type = 10 (按下)
            { x: 100, y: 100 },  // 位置
            0,                    // 修饰键
            Date.now() / 1000,   // 时间戳（秒）
            keyWindow.windowNumber(),  // 窗口编号
            NULL,                 // 上下文
            '\r',                 // 字符（回车）
            '\r',                 // 忽略修饰键的字符
            0,                    // 是否重复
            kVK_Return            // 键码36=回车
        );

        // 创建回车键释放事件
        const keyUpEvent = NSEvent.keyEventWithType_location_modifierFlags_timestamp_windowNumber_context_characters_charactersIgnoringModifiers_isARepeat_keyCode_(
            NSEventTypeKeyUp,     // type = 11 (释放)
            { x: 100, y: 100 },  // 位置
            0,                    // 修饰键
            (Date.now() / 1000) + 0.05,  // 稍后的时间
            keyWindow.windowNumber(),  // 窗口编号
            NULL,                 // 上下文
            '\r',                 // 字符
            '\r',                 // 忽略修饰键的字符
            0,                    // 是否重复
            kVK_Return            // 键码
        );

        // 发送按键按下（根据逆向分析，a4=6可能是按键按下）
        console.log("发送回车键按下...");
        qnsView.handleKeyEvent_eventType_(keyDownEvent, 6);

        // 延迟发送按键释放
        setTimeout(() => {
            console.log("发送回车键释放...");
            qnsView.handleKeyEvent_eventType_(keyUpEvent, 7);  // 猜测7是按键释放
        }, 50);

        console.log("✓ 回车键发送完成");

    } catch (error) {
        console.error(`❌ 发送回车键失败: ${error}`);
    }
}

// 3. 备用方法：使用CGEvent
function sendEnterKeyAlternative() {
    try {
        console.log("尝试使用CGEvent发送回车键...");

        const CGEventCreateKeyboardEvent = Module.findExportByName('CoreGraphics', 'CGEventCreateKeyboardEvent');
        const CGEventPost = Module.findExportByName('CoreGraphics', 'CGEventPost');

        if (CGEventCreateKeyboardEvent && CGEventPost) {
            const kCGHIDEventTap = 0;

            // 发送回车键按下
            const keyDown = new NativeFunction(CGEventCreateKeyboardEvent, 'pointer', ['pointer', 'uint64', 'bool'])(
                NULL,
                kVK_Return,
                true
            );
            new NativeFunction(CGEventPost, 'void', ['uint32', 'pointer'])(kCGHIDEventTap, keyDown);

            // 延迟发送释放
            setTimeout(() => {
                const keyUp = new NativeFunction(CGEventCreateKeyboardEvent, 'pointer', ['pointer', 'uint64', 'bool'])(
                    NULL,
                    kVK_Return,
                    false
                );
                new NativeFunction(CGEventPost, 'void', ['uint32', 'pointer'])(kCGHIDEventTap, keyUp);
                console.log("✓ CGEvent 回车键发送完成");
            }, 50);
        } else {
            console.log("❌ CGEvent API 不可用");
        }
    } catch (error) {
        console.error(`❌ CGEvent方法失败: ${error}`);
    }
}

// 4. 发送文本"123"的函数
function sendText123() {
    try {
        console.log("\n=== 发送文本 '123' ===");

        const NSApplication = ObjC.classes.NSApplication;
        const NSEvent = ObjC.classes.NSEvent;
        const app = NSApplication.sharedApplication();
        const keyWindow = app.keyWindow();

        if (!keyWindow) {
            console.log("❌ 没有找到活动窗口");
            return;
        }

        // 查找QNSView
        function findQNSView(view) {
            if (view.$className === 'QNSView') return view;
            try {
                const subviews = view.subviews();
                const count = subviews.count();
                for (let i = 0; i < count; i++) {
                    const found = findQNSView(subviews.objectAtIndex_(i));
                    if (found) return found;
                }
            } catch (e) {}
            return null;
        }

        const qnsView = findQNSView(keyWindow.contentView());

        if (!qnsView) {
            console.log("❌ 没有找到QNSView");
            return;
        }

        // 要发送的字符和对应的键码
        const textToSend = [
            { char: '1', keyCode: 18 },
            { char: '2', keyCode: 19 },
            { char: '3', keyCode: 20 }
        ];

        // 逐个发送字符
        textToSend.forEach((item, index) => {
            setTimeout(() => {
                try {
                    console.log(`发送字符: ${item.char}`);

                    // 创建按键按下事件
                    const keyDownEvent = NSEvent.keyEventWithType_location_modifierFlags_timestamp_windowNumber_context_characters_charactersIgnoringModifiers_isARepeat_keyCode_(
                        NSEventTypeKeyDown,
                        { x: 100, y: 100 },
                        0,
                        Date.now() / 1000,
                        keyWindow.windowNumber(),
                        NULL,
                        item.char,
                        item.char,
                        0,
                        item.keyCode
                    );

                    // 创建按键释放事件
                    const keyUpEvent = NSEvent.keyEventWithType_location_modifierFlags_timestamp_windowNumber_context_characters_charactersIgnoringModifiers_isARepeat_keyCode_(
                        NSEventTypeKeyUp,
                        { x: 100, y: 100 },
                        0,
                        (Date.now() / 1000) + 0.03,
                        keyWindow.windowNumber(),
                        NULL,
                        item.char,
                        item.char,
                        0,
                        item.keyCode
                    );

                    // 发送按键按下
                    qnsView.handleKeyEvent_eventType_(keyDownEvent, 6);

                    // 延迟发送按键释放
                    setTimeout(() => {
                        qnsView.handleKeyEvent_eventType_(keyUpEvent, 7);
                    }, 30);

                } catch (error) {
                    console.error(`发送字符 ${item.char} 失败: ${error}`);
                }
            }, index * 100);  // 每个字符间隔100ms
        });

        console.log("✓ 文本'123'发送中...");

    } catch (error) {
        console.error(`❌ 发送文本失败: ${error}`);
    }
}

// 5. 组合函数：先发送123，然后回车
function send123AndEnter() {
    console.log("\n=== 开始发送: 123 + 回车 ===");

    // 先发送123
    sendText123();

    // 延迟500ms后发送回车
    setTimeout(() => {
        console.log("\n=== 发送回车键 ===");
        sendEnterKey();
    }, 500);
}

// 6. 通用按键注入函数
function injectKey(keyCode, eventType, characters = '') {
    try {
        const NSApplication = ObjC.classes.NSApplication;
        const NSEvent = ObjC.classes.NSEvent;
        const app = NSApplication.sharedApplication();
        const keyWindow = app.keyWindow();

        if (!keyWindow) {
            console.log("❌ 没有活动窗口");
            return false;
        }

        // 查找QNSView
        function findQNSView(view) {
            if (view.$className === 'QNSView') return view;
            try {
                const subviews = view.subviews();
                for (let i = 0; i < subviews.count(); i++) {
                    const found = findQNSView(subviews.objectAtIndex_(i));
                    if (found) return found;
                }
            } catch (e) {}
            return null;
        }

        const qnsView = findQNSView(keyWindow.contentView());

        if (qnsView) {
            const event = NSEvent.keyEventWithType_location_modifierFlags_timestamp_windowNumber_context_characters_charactersIgnoringModifiers_isARepeat_keyCode_(
                eventType,  // 10=按下, 11=释放
                { x: 100, y: 100 },
                0,
                Date.now() / 1000,
                keyWindow.windowNumber(),
                NULL,
                characters,
                characters,
                0,
                keyCode
            );

            // 根据逆向分析，a4参数：6可能是按下，7可能是释放
            const a4Param = eventType === NSEventTypeKeyDown ? 6 : 7;
            qnsView.handleKeyEvent_eventType_(event, a4Param);

            console.log(`✓ 发送按键: keyCode=${keyCode}, type=${eventType}, a4=${a4Param}`);
            return true;
        }

        return false;

    } catch (error) {
        console.error(`❌ 注入按键失败: ${error}`);
        return false;
    }
}

// 7. 直接调用Qt事件发送（基于逆向分析）
function sendQtKeyEvent(keyCode, text, modifiers = 0) {
    try {
        console.log(`\n=== 直接发送Qt键盘事件: ${text} ===`);

        // 尝试找到QNSView并调用底层函数
        const NSApplication = ObjC.classes.NSApplication;
        const app = NSApplication.sharedApplication();
        const keyWindow = app.keyWindow();

        if (!keyWindow) return;

        // 查找QNSView
        function findQNSView(view) {
            if (view.$className === 'QNSView') return view;
            try {
                const subviews = view.subviews();
                for (let i = 0; i < subviews.count(); i++) {
                    const found = findQNSView(subviews.objectAtIndex_(i));
                    if (found) return found;
                }
            } catch (e) {}
            return null;
        }

        const qnsView = findQNSView(keyWindow.contentView());

        if (qnsView && qnsView.handleKeyEvent) {
            // 创建模拟的事件对象
            const fakeEvent = {
                keyCode: function() { return keyCode; },
                characters: function() { return text; },
                charactersIgnoringModifiers: function() { return text; },
                timestamp: function() { return Date.now() / 1000; },
                modifierFlags: function() { return modifiers; },
                isARepeat: function() { return 0; }
            };

            // 包装成ObjC对象
            const eventWrapper = new ObjC.Object(fakeEvent);

            // 发送事件
            qnsView.handleKeyEvent_eventType_(eventWrapper, 6);

            console.log(`✓ Qt事件发送: ${text} (keyCode: ${keyCode})`);
        }

    } catch (error) {
        console.error(`❌ Qt事件发送失败: ${error}`);
    }
}

// 8. 导出函数到全局
global.sendEnterKey = sendEnterKey;
global.sendText123 = sendText123;
global.send123AndEnter = send123AndEnter;
global.injectKey = injectKey;
global.sendQtKeyEvent = sendQtKeyEvent;

// 9. 创建交互式菜单
function showMenu() {
    console.log("\n" + "=".repeat(50));
    console.log("🎹 键盘注入器 - 纯JS版本");
    console.log("=".repeat(50));
    console.log("可用命令:");
    console.log("1. sendEnterKey()     - 发送回车键");
    console.log("2. sendText123()      - 发送文本 '123'");
    console.log("3. send123AndEnter()  - 发送 '123' 然后回车");
    console.log("4. injectKey(36, 10)  - 发送回车键按下");
    console.log("5. injectKey(36, 11)  - 发送回车键释放");
    console.log("6. sendQtKeyEvent(18, '1') - 直接发送Qt事件");
    console.log("=".repeat(50));
    console.log("示例: 发送 '123' 然后回车:");
    console.log("  send123AndEnter()");
    console.log("=".repeat(50));
}

// 10. 自动执行（可选）
// 取消下面行的注释可以自动发送
// setTimeout(send123AndEnter, 1000);

// 显示菜单
showMenu();

console.log("\n✅ 键盘注入器加载完成！");
console.log("📝 输入命令开始注入键盘事件...");