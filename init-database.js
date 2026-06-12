const { initDatabase } = require('./database');

async function main() {
  console.log('🔄 جاري تهيئة قاعدة البيانات...');
  await initDatabase();
  console.log('✅ تم الانتهاء!');
  process.exit(0);
}

main().catch(err => {
  console.error('❌ خطأ:', err);
  process.exit(1);
});
