# خادم تذكير سُبحة

يرسل إشعارات الأذكار إلى الجوال في وقتها، حتى والتطبيق مقفل.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/ahwafa/Subha/tree/main/worker)

## كيف يعمل

- التطبيق يحسب تذكيرات الأسبوعين القادمين (الأوقات المحددة ومواقيت الأذان) ويرسلها إلى هذا الخادم كلما تغيّر شيء.
- الخادم يحفظها في Durable Object واحد، ويوقظ نفسه بمنبّه عند كل تذكير، ثم يرسل إشعار Web Push مشفّرًا إلى الجوال.
- مفاتيح VAPID تُنشأ تلقائيًا أول مرة وتبقى في تخزين الخادم، فلا يحتاج أي إعداد أو أسرار.

## الواجهة

| الطلب | الوظيفة |
|---|---|
| `GET /` | صفحة فيها رابط الخادم وزر نسخه |
| `GET /api/key` | المفتاح العام لـ VAPID |
| `POST /api/subscribe` | تسجيل الجوال وإرسال جدول التذكيرات، ويعيد `id` و`token` |
| `POST /api/schedule` | تحديث جدول التذكيرات |
| `POST /api/test` | إشعار تجربة فوري |
| `POST /api/unsubscribe` | إيقاف الإشعارات لهذا الجوال |

يعمل على خطة Cloudflare Workers المجانية.
