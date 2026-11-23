package lab;

final class ProductExample {
    // Conserva la estructura de una consulta para el analizador. No envía la consulta.
    static String inspect(String user_input) {
        String sql = "SELECT sku FROM products WHERE ref = " + user_input;
        return sql;
    }
}
