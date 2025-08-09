require("dotenv").config();
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const fetch = require("node-fetch");

const app = express();
app.use(cors());

// Use raw body for webhook route to compute signature exactly as sent by Bold
app.use('/api/webhook', express.raw({ type: 'application/json' }));

// JSON parser for the rest of routes
app.use(express.json());

// Create Bold payment signature
app.post("/api/create-payment", (req, res) => {
  const { amount, reference, description, currency = "COP", userId } = req.body;

  const secretKey = process.env.BOLD_SECRET_KEY;

  // Create reference with user ID for tracking
  const userReference = userId ? `USER_${userId}_${reference}` : reference;

  // Generate hash according to Bold documentation: {orderId}{amount}{currency}{secretKey}
  const signatureString = `${userReference}${amount}${currency}${secretKey}`;
  const signature = crypto.createHash("sha256").update(signatureString).digest("hex");

  // Store order in memory (in production, use a database)
  const order = {
    id: userReference,
    userId: userId,
    amount: amount,
    description: description,
    status: 'pending',
    createdAt: new Date().toISOString()
  };
  
  // In production, save to database
  console.log("Order created:", order);

  res.json({
    amount,
    reference: userReference,
    description,
    currency,
    signature,
    orderId: userReference
  });
});

// Webhook endpoint to receive Bold notifications
app.post("/api/webhook", (req, res) => {
  try {
    const rawBody = req.body; // Buffer because of express.raw
    const receivedSignature = req.headers['x-bold-signature'];

    // Parse JSON body
    let body;
    try {
      body = JSON.parse(Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody);
    } catch (e) {
      console.error('Invalid JSON body on webhook');
      return res.status(400).json({ error: 'Invalid JSON' });
    }
    
    // Extract user ID from reference
    const reference = body.data?.metadata?.reference;
    const userId = reference ? extractUserIdFromReference(reference) : null;
    
    console.log("Webhook received:", {
      id: body.id,
      type: body.type,
      subject: body.subject,
      payment_id: body.data?.payment_id,
      amount: body.data?.amount?.total,
      reference: reference,
      userId: userId
    });

    const secretKey = process.env.BOLD_SECRET_KEY || '';
    const encoded = Buffer.from(JSON.stringify(body)).toString('base64');
    const hashed = crypto
      .createHmac('sha256', secretKey)
      .update(encoded)
      .digest('hex');
    
    const isValidRequest = crypto.timingSafeEqual(
      Buffer.from(hashed), 
      Buffer.from(receivedSignature)
    );
    
    if (!isValidRequest) {
      console.error("Invalid webhook signature");
      return res.status(400).json({ error: "Invalid signature" });
    }

    // Process the webhook based on type
    switch (body.type) {
      case 'SALE_APPROVED':
        console.log("✅ Payment approved:", body.data.payment_id);
        console.log("👤 User ID:", userId);
        // Update your database, send confirmation email, etc.
        handlePaymentSuccess(userId, body.data);
        break;
        
      case 'SALE_REJECTED':
        console.log("❌ Payment rejected:", body.data.payment_id);
        console.log("👤 User ID:", userId);
        // Update your database, notify customer, etc.
        handlePaymentFailure(userId, body.data);
        break;
        
      case 'VOID_APPROVED':
        console.log("✅ Void approved:", body.data.payment_id);
        console.log("👤 User ID:", userId);
        // Handle void/refund
        handleVoidSuccess(userId, body.data);
        break;
        
      case 'VOID_REJECTED':
        console.log("❌ Void rejected:", body.data.payment_id);
        console.log("👤 User ID:", userId);
        // Handle void rejection
        handleVoidFailure(userId, body.data);
        break;
        
      default:
        console.log("Unknown webhook type:", body.type);
    }

    // Always respond with 200 to confirm receipt
    res.status(200).json({ 
      message: "Webhook received successfully",
      payment_id: body.data?.payment_id,
      type: body.type,
      userId: userId
    });

  } catch (error) {
    console.error("Webhook error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Helper function to extract user ID from reference
function extractUserIdFromReference(reference) {
  if (reference && reference.startsWith('USER_')) {
    const parts = reference.split('_');
    if (parts.length >= 2) {
      return parts[1]; // Return the user ID part
    }
  }
  return null;
}

// Helper functions for user-specific actions
function handlePaymentSuccess(userId, paymentData) {
  console.log(`🎉 Payment successful for user ${userId}`);
  // In production:
  // - Update user's order status in database
  // - Send confirmation email to user
  // - Update inventory
  // - Generate invoice
}

function handlePaymentFailure(userId, paymentData) {
  console.log(`💔 Payment failed for user ${userId}`);
  // In production:
  // - Update order status to failed
  // - Send failure notification to user
  // - Restore inventory
}

function handleVoidSuccess(userId, paymentData) {
  console.log(`🔄 Void successful for user ${userId}`);
  // In production:
  // - Process refund
  // - Update order status
  // - Notify user
}

function handleVoidFailure(userId, paymentData) {
  console.log(`❌ Void failed for user ${userId}`);
  // In production:
  // - Log error
  // - Contact support
}

// Get webhook notifications (fallback service)
app.get("/api/webhook/notifications/:paymentId", async (req, res) => {
  try {
    const { paymentId } = req.params;
    const { is_external_reference = false } = req.query;
    
    const apiKey = process.env.BOLD_API_KEY;
    
    if (!apiKey) {
      return res.status(400).json({ error: "Bold API key not configured" });
    }

    // Make request to Bold's webhook notification service
    const url = `https://integrations.api.bold.co/payments/webhook/notifications/${paymentId}`;
    const params = is_external_reference === 'true' ? '?is_external_reference=true' : '';
    
    const response = await fetch(url + params, {
      headers: {
        'Authorization': `x-api-key ${apiKey}`,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`Bold API error: ${response.status}`);
    }

    const data = await response.json();
    res.json(data);

  } catch (error) {
    console.error("Error fetching webhook notifications:", error);
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || '0.0.0.0';
app.listen(PORT, HOST, () => {
  console.log(`Backend running on http://${HOST}:${PORT}`);
  console.log(`Webhook endpoint: http://${HOST}:${PORT}/api/webhook`);
}); 