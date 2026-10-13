#!/usr/bin/env python3
"""
Скрипт для анализа кода и выявления проблем
"""
import re
import ast
import os
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple

class CodeAnalyzer:
    def __init__(self, source_path: str):
        self.source_path = Path(source_path)
        self.issues = defaultdict(list)
        self.stats = {
            'total_files': 0,
            'total_lines': 0,
            'total_functions': 0,
            'total_classes': 0,
        }
    
    def analyze_file(self, file_path: Path):
        """Анализирует один файл"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
                
            self.stats['total_files'] += 1
            self.stats['total_lines'] += len(lines)
            
            # Анализ через AST
            try:
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        self.stats['total_functions'] += 1
                        self._analyze_function(node, file_path)
                    elif isinstance(node, ast.ClassDef):
                        self.stats['total_classes'] += 1
            except SyntaxError:
                self.issues['syntax_errors'].append(f"{file_path}: Syntax error")
            
            # Анализ через регулярные выражения
            self._analyze_patterns(content, file_path)
            
        except Exception as e:
            self.issues['errors'].append(f"{file_path}: {str(e)}")
    
    def _analyze_function(self, node: ast.FunctionDef, file_path: Path):
        """Анализирует функцию на проблемы"""
        # Проверка на слишком длинные функции
        if node.end_lineno and node.lineno:
            length = node.end_lineno - node.lineno
            if length > 100:
                self.issues['long_functions'].append(
                    f"{file_path}:{node.lineno}: {node.name} ({length} lines)"
                )
        
        # Проверка на общие except
        for child in ast.walk(node):
            if isinstance(child, ast.ExceptHandler):
                if child.type is None or (isinstance(child.type, ast.Name) and child.type.id == 'Exception'):
                    self.issues['broad_except'].append(
                        f"{file_path}:{child.lineno}: {node.name} - bare except or Exception"
                    )
    
    def _analyze_patterns(self, content: str, file_path: Path):
        """Анализирует паттерны через регулярные выражения"""
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Проверка на TODO
            if re.search(r'\bTODO\b', line, re.IGNORECASE):
                self.issues['todos'].append(f"{file_path}:{i}: {line.strip()}")
            
            # Проверка на FIXME
            if re.search(r'\bFIXME\b', line, re.IGNORECASE):
                self.issues['fixmes'].append(f"{file_path}:{i}: {line.strip()}")
            
            # Проверка на потенциально опасные паттерны
            if re.search(r'except\s*:', line):
                self.issues['bare_except'].append(f"{file_path}:{i}: bare except")
            
            # Проверка на отсутствие проверок на None
            if re.search(r'\.(.*)\(\)', line) and 'if' not in line and 'or' not in line:
                if any(pattern in line for pattern in ['db.session.get', '.query.filter']):
                    if 'if' not in lines[max(0, i-2):i+1] and 'None' not in lines[max(0, i-2):i+1]:
                        self.issues['potential_none'].append(
                            f"{file_path}:{i}: Potential None access: {line.strip()[:80]}"
                        )
    
    def analyze_directory(self, directory: Path = None):
        """Анализирует директорию"""
        if directory is None:
            directory = self.source_path
        
        for py_file in directory.rglob('*.py'):
            # Пропускаем виртуальные окружения
            if '.venv' in str(py_file) or 'venv' in str(py_file):
                continue
            self.analyze_file(py_file)
    
    def print_report(self):
        """Выводит отчет"""
        print("=" * 80)
        print("АНАЛИЗ КОДА - ОТЧЕТ")
        print("=" * 80)
        print(f"\nСтатистика:")
        print(f"  Файлов: {self.stats['total_files']}")
        print(f"  Строк кода: {self.stats['total_lines']}")
        print(f"  Функций: {self.stats['total_functions']}")
        print(f"  Классов: {self.stats['total_classes']}")
        
        print("\n" + "=" * 80)
        print("НАЙДЕННЫЕ ПРОБЛЕМЫ:")
        print("=" * 80)
        
        for category, items in sorted(self.issues.items()):
            if items:
                print(f"\n{category.upper()} ({len(items)}):")
                for item in items[:10]:  # Показываем первые 10
                    print(f"  - {item}")
                if len(items) > 10:
                    print(f"  ... и еще {len(items) - 10} проблем")


if __name__ == '__main__':
    analyzer = CodeAnalyzer('/home/nmc-admin/NMC_WG/src')
    analyzer.analyze_directory()
    analyzer.print_report()

