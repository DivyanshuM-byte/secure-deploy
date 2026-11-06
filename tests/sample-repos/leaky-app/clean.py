"""Clean module with zero hardcoded secrets or high-entropy tokens."""


def calculate_order_total(unit_price: float, quantity: int, discount_rate: float = 0.0) -> float:
    """Compute total price after applying an optional discount."""
    if quantity <= 0 or unit_price < 0:
        return 0.0
    subtotal = unit_price * quantity
    return round(subtotal * (1.0 - discount_rate), 2)
