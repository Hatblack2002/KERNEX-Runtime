package com.kernex.runtime;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

public final class MainActivity extends Activity {
    private static final int PICK_PE = 42;
    private TextView status;

    static { System.loadLibrary("kernex_android"); }
    private native String nativeStatus();
    private native String inspectPe(byte[] fileBytes);

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(24, 32, 24, 24);
        layout.setGravity(Gravity.TOP);
        TextView title = new TextView(this);
        title.setText("KERNEX Runtime");
        title.setTextSize(26);
        layout.addView(title, new LinearLayout.LayoutParams(-1, -2));
        TextView subtitle = new TextView(this);
        subtitle.setText("Experimental native ARM64 shell · PE inspection and limited x86-32 research");
        subtitle.setTextSize(14);
        layout.addView(subtitle, new LinearLayout.LayoutParams(-1, -2));
        Button pick = new Button(this);
        pick.setText("Select Windows EXE / DLL");
        pick.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            intent.setType("*/*");
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            startActivityForResult(intent, PICK_PE);
        });
        layout.addView(pick, new LinearLayout.LayoutParams(-1, -2));
        status = new TextView(this);
        status.setText(nativeStatus());
        status.setTextIsSelectable(true);
        status.setTextSize(14);
        layout.addView(status, new LinearLayout.LayoutParams(-1, -2));
        ScrollView scroll = new ScrollView(this);
        scroll.addView(layout);
        setContentView(scroll);
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != PICK_PE || resultCode != RESULT_OK || data == null || data.getData() == null) return;
        Uri uri = data.getData();
        try (InputStream input = getContentResolver().openInputStream(uri);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            if (input == null) throw new IllegalStateException("Unable to open selected file");
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (output.size() + count > 256 * 1024 * 1024) throw new IllegalArgumentException("File exceeds 256 MiB safety limit");
                output.write(buffer, 0, count);
            }
            status.setText(inspectPe(output.toByteArray()));
        } catch (Exception e) {
            status.setText("Could not inspect file: " + e.getMessage());
        }
    }
}
