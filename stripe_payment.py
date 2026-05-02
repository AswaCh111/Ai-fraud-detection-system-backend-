import stripe
import os
from dotenv import load_dotenv

load_dotenv()

stripe.api_key = os.getenv('STRIPE_SECRET_KEY', '')

def create_stripe_products():
    """Create subscription products in Stripe (run once)"""
    if not stripe.api_key:
        print("⚠️ STRIPE_SECRET_KEY not set")
        return {}
    
    products = {}
    
    try:
        # Pro plan - $49/month
        pro_product = stripe.Product.create(
            name='FraudShield Pro',
            description='Advanced fraud detection for professionals',
            metadata={'plan_type': 'pro'}
        )
        pro_price = stripe.Price.create(
            product=pro_product.id,
            unit_amount=4900,
            currency='usd',
            recurring={'interval': 'month'}
        )
        products['pro'] = {
            'product_id': pro_product.id,
            'price_id': pro_price.id
        }
        print(f"✅ Created Pro plan: {pro_price.id}")
        
        # Enterprise plan - $199/month
        enterprise_product = stripe.Product.create(
            name='FraudShield Enterprise',
            description='Enterprise-grade fraud protection',
            metadata={'plan_type': 'enterprise'}
        )
        enterprise_price = stripe.Price.create(
            product=enterprise_product.id,
            unit_amount=19900,
            currency='usd',
            recurring={'interval': 'month'}
        )
        products['enterprise'] = {
            'product_id': enterprise_product.id,
            'price_id': enterprise_price.id
        }
        print(f"✅ Created Enterprise plan: {enterprise_price.id}")
        
    except Exception as e:
        print(f"❌ Stripe error: {e}")
    
    return products

def get_price_id(plan):
    """Get Stripe price ID for a plan"""
    price_ids = {
        'pro': os.getenv('STRIPE_PRO_PRICE_ID', 'price_pro_default'),
        'enterprise': os.getenv('STRIPE_ENTERPRISE_PRICE_ID', 'price_enterprise_default')
    }
    return price_ids.get(plan)

# Export for use in app.py
__all__ = ['create_stripe_products', 'get_price_id']