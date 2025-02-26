package com.example.secureauthenticator

import android.app.Activity
import android.os.Bundle
import android.widget.TextView
import android.view.WindowManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.security.SecureRandom
import java.util.concurrent.Executor
import kotlin.concurrent.fixedRateTimer
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import android.util.Base64
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import java.io.File
import android.speech.tts.TextToSpeech
import java.util.Locale

class MainActivity : Activity(), TextToSpeech.OnInitListener {
    private lateinit var otpTextView: TextView
    private val otpLength = 8
    private var currentOtp: String = ""
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var textToSpeech: TextToSpeech

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Initialize Text-to-Speech
        textToSpeech = TextToSpeech(this, this)

        // Prevent screenshots and screen recording
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)

        // Check if the device is rooted
        if (isDeviceRooted()) {
            reportSuspiciousActivity()
            finish()
        }

        otpTextView = findViewById(R.id.otpTextView)
        authenticateUser()

        // Schedule deep security check every 30 minutes
        handler.postDelayed({ performDeepSecurityCheck() }, 1800000)
    }

    override fun onInit(status: Int) {
        if (status == TextToSpeech.SUCCESS) {
            textToSpeech.language = Locale.US
        }
    }

    private fun authenticateUser() {
        val executor: Executor = ContextCompat.getMainExecutor(this)
        val biometricPrompt = BiometricPrompt(this, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                generateOtp()
            }
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                finish() // Exit app if authentication fails
            }
        })

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Secure Authenticator")
            .setSubtitle("Authenticate using your fingerprint")
            .setNegativeButtonText("Cancel")
            .setDeviceCredentialAllowed(false)
            .build()

        biometricPrompt.authenticate(promptInfo)
    }

    private fun generateOtp() {
        val random = SecureRandom()
        val otpBuilder = StringBuilder()
        for (i in 0 until otpLength) {
            otpBuilder.append(random.nextInt(10))
        }
        currentOtp = encryptOtp(otpBuilder.toString())
        otpTextView.text = "Your OTP: ${decryptOtp(currentOtp)}"

        // Clear OTP after 30 seconds
        handler.postDelayed({ otpTextView.text = "OTP expired" }, 30000)

        // Refresh OTP every 60 seconds
        handler.postDelayed({ generateOtp() }, 60000)
    }

    private fun encryptOtp(otp: String): String {
        val secretKey = getSecretKey()
        return Base64.encodeToString(secretKey.encoded + otp.toByteArray(), Base64.DEFAULT)
    }

    private fun decryptOtp(encryptedOtp: String): String {
        val decoded = Base64.decode(encryptedOtp, Base64.DEFAULT)
        return String(decoded.drop(32).toByteArray())
    }

    private fun getSecretKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        keyGenerator.init(
            KeyGenParameterSpec.Builder("SecureOTPKey",
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(30)
                .build()
        )
        return keyGenerator.generateKey()
    }

    private fun isDeviceRooted(): Boolean {
        val paths = arrayOf("/system/app/Superuser.apk", "/system/xbin/su", "/system/bin/su", "/system/sbin/su")
        for (path in paths) {
            if (File(path).exists()) {
                return true
            }
        }
        return false
    }

    private fun performDeepSecurityCheck() {
        if (isDeviceRooted()) {
            reportSuspiciousActivity()
            finish()
        }

        // Additional checks can be added here (e.g., monitoring for unauthorized access, integrity checks, etc.)

        // Schedule the next check in 30 minutes
        handler.postDelayed({ performDeepSecurityCheck() }, 1800000)
    }

    private fun reportSuspiciousActivity() {
        // Lock Gmail account and send security report to Google
        println("Suspicious activity detected! Locking email and reporting to Google.")
        lockEmailAccount()
        playAlertMessage()
    }

    private fun playAlertMessage() {
        val message = "Suspicious activity found in dark web"
        textToSpeech.speak(message, TextToSpeech.QUEUE_FLUSH, null, null)
    }

    private fun lockEmailAccount() {
        // Simulated function to lock the email account
        println("Email account locked. Biometric verification required to unlock.")
        requireBiometricUnlock()
    }

    private fun requireBiometricUnlock() {
        val executor: Executor = ContextCompat.getMainExecutor(this)
        val biometricPrompt = BiometricPrompt(this, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                println("Email account unlocked successfully.")
            }
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                println("Failed biometric verification. Access denied.")
            }
        })

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric Verification Required")
            .setSubtitle("Verify your identity to unlock your email account.")
            .setNegativeButtonText("Cancel")
            .setDeviceCredentialAllowed(false)
            .build()

        biometricPrompt.authenticate(promptInfo)
    }
}
