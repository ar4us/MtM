#!/bin/bash

# ألوان للعرض
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # بدون لون

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════╗"
echo "║      MITM Tool - سكربت التثبيت           ║"
echo "╚═══════════════════════════════════════════╝"
echo -e "${NC}"

# التحقق من صلاحيات root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] يجب تشغيل سكربت التثبيت بصلاحيات root${NC}"
   echo -e "${YELLOW}استخدم: sudo bash install.sh${NC}"
   exit 1
fi

echo -e "${GREEN}[+] بدء عملية التثبيت...${NC}\n"

# 1. تحديث النظام
echo -e "${BLUE}[*] تحديث قوائم الحزم...${NC}"
apt-get update -qq

# 2. تثبيت Python3 و pip
echo -e "${BLUE}[*] التأكد من تثبيت Python3 و pip...${NC}"
apt-get install -y python3 python3-pip -qq

# 3. تثبيت المكتبات المطلوبة
echo -e "${BLUE}[*] تثبيت المكتبات المطلوبة...${NC}"
pip3 install scapy netifaces -q

# 4. إعطاء صلاحيات التنفيذ
echo -e "${BLUE}[*] إعطاء صلاحيات التنفيذ...${NC}"
chmod +x mitm_tool.py

# 5. إنشاء رابط رمزي (اختياري)
echo -e "${BLUE}[*] هل تريد إنشاء أمر عام للأداة؟ (y/n)${NC}"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    cp mitm_tool.py /usr/local/bin/mitm-tool
    chmod +x /usr/local/bin/mitm-tool
    echo -e "${GREEN}[+] يمكنك الآن تشغيل الأداة من أي مكان باستخدام: sudo mitm-tool${NC}"
fi

echo -e "\n${GREEN}╔═══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║      ✅ تم التثبيت بنجاح!                ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════╝${NC}\n"

echo -e "${YELLOW}للتشغيل:${NC}"
echo -e "  ${BLUE}sudo python3 mitm_tool.py${NC}"
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    echo -e "  ${BLUE}أو: sudo mitm-tool${NC}"
fi

echo -e "\n${RED}⚠️  تذكير: استخدم الأداة للأغراض التعليمية فقط!${NC}\n"