import os
import glob
import json
import subprocess
import sys

class Config:
    DOMAIN_LIST_DIR = 'domain-list-community/data'
    REFILTER_DIR = 'Re-filter-lists'
    CACHE_FILE = 'cache/intersected_cache.json'
    EXCLUDE_FILE = 'exclude.txt'
    ALTERNATIVE_FILE = 'alternative.txt'
    OUTPUT_DIR = 'output'

class TextListManager:
    @staticmethod
    def load_user_list(filepath, default_header):
        if not os.path.exists(filepath):
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(default_header)
            return []
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = [line.strip().split('#')[0].strip() for line in f]
            return [line for line in lines if line]

    @staticmethod
    def load_refilter_domains(refilter_dir):
        blocked_domains = set()
        for filepath in glob.glob(os.path.join(refilter_dir, '*.lst')):
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    domain = line.split('#')[0].strip()
                    if domain:
                        blocked_domains.add(domain)
        return list(blocked_domains)

    @staticmethod
    def get_cidr_categories(output_dir):
        """Парсит файлы *-cidr.txt и возвращает словарь: category -> set of cidrs"""
        cidr_cache = {}
        for filepath in glob.glob(os.path.join(output_dir, '*-cidr.txt')):
            basename = os.path.basename(filepath)
            
            # Поддержка виртуальных кастомных имен: "custom_NAME-cidr.txt" -> "custom:NAME"
            if basename.startswith('custom_') and basename.endswith('-cidr.txt'):
                category = 'custom:' + basename[7:-9]
            else:
                category = basename.replace('-cidr.txt', '')
                
            with open(filepath, 'r', encoding='utf-8') as f:
                cidrs = {line.split('#')[0].strip() for line in f if line.split('#')[0].strip()}
                if cidrs:
                    cidr_cache[category] = cidrs
        return cidr_cache

class DomainManager:
    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.parsed_cache = {}

    def resolve_rules(self, category, call_stack=None):
        if call_stack is None:
            call_stack = set()
            
        if category in call_stack:
            return {'domain': set(), 'domain_suffix': set(), 'domain_keyword': set(), 'domain_regex': set()}
        if category in self.parsed_cache:
            return self.parsed_cache[category]
            
        call_stack.add(category)
        filepath = os.path.join(self.data_dir, category)
        rules = {'domain': set(), 'domain_suffix': set(), 'domain_keyword': set(), 'domain_regex': set()}
        
        if not os.path.isfile(filepath):
            call_stack.remove(category)
            return rules
            
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.split('#')[0].split('@')[0].strip()
                if not line: continue
                if line.startswith('include:'):
                    inc_file = line[8:]
                    inc_rules = self.resolve_rules(inc_file, call_stack)
                    for k in rules:
                        rules[k].update(inc_rules[k])
                elif line.startswith('full:'): rules['domain'].add(line[5:])
                elif line.startswith('domain:'): rules['domain_suffix'].add(line[7:])
                elif line.startswith('keyword:'): rules['domain_keyword'].add(line[8:])
                elif line.startswith('regexp:'): rules['domain_regex'].add(line[7:])
                else: rules['domain_suffix'].add(line)
                    
        call_stack.remove(category)
        self.parsed_cache[category] = rules
        return rules

    def find_intersections(self, blocked_domains):
        exact_map = {}
        suffix_map = {}
        
        for category, rules in self.parsed_cache.items():
            if any(x in category for x in ['geolocation', 'category', 'tld']):
                continue
                
            for d in rules['domain']:
                exact_map.setdefault(d, set()).add(category)
            for s in rules['domain_suffix']:
                suffix_map.setdefault(s, set()).add(category)
                
        intersected_categories = set()
        for domain in blocked_domains:
            if domain in exact_map:
                intersected_categories.update(exact_map[domain])
                
            parts = domain.split('.')
            for i in range(len(parts)):
                sub = '.'.join(parts[i:])
                if sub in suffix_map:
                    intersected_categories.update(suffix_map[sub])
                    
        return list(intersected_categories)

class SingBoxCompiler:
    def __init__(self, output_dir, parsed_domain_cache, parsed_cidr_cache):
        self.output_dir = output_dir
        self.parsed_domain_cache = parsed_domain_cache
        self.parsed_cidr_cache = parsed_cidr_cache

    def compile(self, name, category_list):
        print(f"\n⚙️  Сборка SRS: {name} (Категорий: {len(category_list)})...")
        if not category_list:
            print(f"⚠️  Пропуск {name}: нет подходящих категорий.")
            return

        final_rules = {'domain': set(), 'domain_suffix': set(), 'domain_keyword': set(), 'domain_regex': set(), 'ip_cidr': set()}
        
        for category in category_list:
            # 1. Применяем домены (если такие есть для этой категории)
            if category in self.parsed_domain_cache:
                rules = self.parsed_domain_cache[category]
                for k in ['domain', 'domain_suffix', 'domain_keyword', 'domain_regex']:
                    final_rules[k].update(rules[k])
            
            # 2. Применяем CIDR-подсети (если category-cidr.txt существует)
            if category in self.parsed_cidr_cache:
                final_rules['ip_cidr'].update(self.parsed_cidr_cache[category])
                
        singbox_rules = {}
        for rule_type, rules_set in final_rules.items():
            clean_rules = []
            for item in rules_set:
                item = str(item).strip()
                if item.startswith('.'): item = item[1:]
                if item: clean_rules.append(item)
            if clean_rules:
                singbox_rules[rule_type] = sorted(list(set(clean_rules)))
                
        rule_set_data = {
            "version": 1,
            "rules": [singbox_rules]
        }
        
        json_path = os.path.join(self.output_dir, f'{name}.json')
        srs_path = os.path.join(self.output_dir, f'{name}.srs')
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(rule_set_data, f, ensure_ascii=False, indent=2)
            
        try:
            if os.path.exists(srs_path):
                os.remove(srs_path)
            subprocess.run(['sing-box', 'rule-set', 'compile', json_path, '-o', srs_path], check=True)
            print(f"🎉 Готово: {srs_path} (размер: {os.path.getsize(srs_path)} байт)")
        except Exception as e:
            print(f"❌ Ошибка компиляции {srs_path}: {e}")

def main():
    if not os.path.exists(Config.OUTPUT_DIR): os.makedirs(Config.OUTPUT_DIR)
    if not os.path.exists(os.path.dirname(Config.CACHE_FILE)): os.makedirs(os.path.dirname(Config.CACHE_FILE))

    domain_mgr = DomainManager(Config.DOMAIN_LIST_DIR)
    intersected_categories = []

    # --------- КЕШИРОВАНИЕ ДОМЕНОВ ---------
    if os.path.exists(Config.CACHE_FILE):
        print("⚡ Загружаем результаты пересечения доменов из кеша...")
        with open(Config.CACHE_FILE, 'r', encoding='utf-8') as f:
            cache_data = json.load(f)
            intersected_categories = cache_data.get("intersected_categories", [])
            # Json loads sets as lists, need to convert them back to sets for DomainManager
            cache_parsed = cache_data.get("parsed_cache", {})
            for k, v in cache_parsed.items():
                domain_mgr.parsed_cache[k] = {rule_key: set(rule_val) for rule_key, rule_val in v.items()}
    else:
        print("🌐 Парсинг файлов из domain-list-community...")
        all_files = [
            os.path.basename(f) for f in glob.glob(os.path.join(Config.DOMAIN_LIST_DIR, '*')) 
            if os.path.isfile(f) and not any(x in os.path.basename(f) for x in ['geolocation', 'category', 'tld'])
        ]
        for filename in all_files:
            domain_mgr.resolve_rules(filename)

        print("🌐 Загрузка заблокированных доменов из Re-filter-lists...")
        blocked_domains = TextListManager.load_refilter_domains(Config.REFILTER_DIR)
        
        print("🔍 Поиск пересечений...")
        intersected_categories = domain_mgr.find_intersections(blocked_domains)
        
        # Сохраняем кэш
        with open(Config.CACHE_FILE, 'w', encoding='utf-8') as f:
            serializable_cache = {k: {rk: list(rv) for rk, rv in v.items()} for k, v in domain_mgr.parsed_cache.items()}
            json.dump({"intersected_categories": intersected_categories, "parsed_cache": serializable_cache}, f, ensure_ascii=False)

    print(f"Всего затронуто категорий доменов РКН: {len(intersected_categories)}\n")

    # --------- ЗАГРУЗКА CIDR-СПИСКОВ ---------
    parsed_cidr_cache = TextListManager.get_cidr_categories(Config.OUTPUT_DIR)
    print(f"📦 Доступны CIDR-подсети для виртуальных категорий: {list(parsed_cidr_cache.keys())}\n")

    # --------- МАРШРУТИЗАЦИЯ ---------
    alternative_list = TextListManager.load_user_list(
        Config.ALTERNATIVE_FILE, 
        "# Впишите названия файлов (например google, discord, telegram)\n# которые нужно вынести в отдельный SRS (альтернативный маршрут)\n# Сюда же можно вписывать и виртуальные имена для CIDR, например 'asn'\n"
    )
    
    real_exclude_list = TextListManager.load_user_list(
        Config.EXCLUDE_FILE, 
        "# Впишите названия файлов, которые вообще НЕ ДОЛЖНЫ попадать ни в какие output-файлы\n"
    )

    # Формируем единый глобальный набор активных категорий
    # (Все категории с доменами ИЗ пересечения + все категории, для которых есть отдельные *-cidr.txt)
    all_active_categories = set(intersected_categories)
    all_active_categories.update(parsed_cidr_cache.keys())

    # Фильтруем Полные исключения (Exclude)
    allowed_categories = [c for c in all_active_categories if c not in real_exclude_list]

    # Разделяем на Альтернативный и Базовый маршруты
    route_alternative = [c for c in allowed_categories if c in alternative_list]
    route_filtered = [c for c in allowed_categories if c not in alternative_list]

    # --------- КОМПИЛЯЦИЯ SRS ---------
    compiler = SingBoxCompiler(Config.OUTPUT_DIR, domain_mgr.parsed_cache, parsed_cidr_cache)
    
    # 1. Весь список (без учета alternative, но БЕЗ exclude)
    compiler.compile('intersected_all', allowed_categories)
    
    # 2. Только альтернативные домены (и их CIDR)
    compiler.compile('intersected_alternative_only', route_alternative)
    
    # 3. Базовый список без alternative и без exclude (Тут и будут 16 КБ блоки из 'asn', если оно не в alternative/exclude)
    compiler.compile('intersected_filtered', route_filtered)

    print("\n✅ ВЕСЬ ПРОЦЕСС ЗАВЕРШЁН. Результаты в папке output/")

if __name__ == "__main__":
    main()