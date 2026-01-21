#!/bin/bash
# Setup script for PostgreSQL database using Docker

set -e

echo "🐳 Starting PostgreSQL with Docker..."

# Start PostgreSQL container
docker-compose -f docker-compose.db.yml up -d

echo "⏳ Waiting for PostgreSQL to be ready..."
sleep 5

# Wait for health check
until docker exec waf_postgres pg_isready -U waf_user -d waf_db > /dev/null 2>&1; do
    echo "   Waiting for database..."
    sleep 2
done

echo "✅ PostgreSQL is ready!"

# Show connection info
echo ""
echo "📊 Database Connection Info:"
echo "   Host: localhost"
echo "   Port: 5432"
echo "   Database: waf_db"
echo "   Username: waf_user"
echo "   Password: waf_password"
echo ""

# Test connection
echo "🔍 Testing database connection..."
docker exec waf_postgres psql -U waf_user -d waf_db -c "SELECT version();" > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "✅ Database connection successful!"
    
    # Show tables
    echo ""
    echo "📋 Database tables:"
    docker exec waf_postgres psql -U waf_user -d waf_db -c "\dt"
    
    # Show users
    echo ""
    echo "👥 Users in database:"
    docker exec waf_postgres psql -U waf_user -d waf_db -c "SELECT username, email, role, created_at FROM users;"
else
    echo "❌ Database connection failed!"
    exit 1
fi

echo ""
echo "🎉 PostgreSQL setup complete!"
echo "   To stop: docker-compose -f docker-compose.db.yml down"
echo "   To view logs: docker-compose -f docker-compose.db.yml logs -f"
