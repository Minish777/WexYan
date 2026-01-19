#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WexYan Ultimate v8.1 - Professional Edition
Оптимизированная и стабильная версия
"""

import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import customtkinter as ctk
import json
import os
import sys
import ctypes
import threading
from datetime import datetime
import time
import hashlib
from pathlib import Path
import logging
from logging.handlers import RotatingFileHandler
import traceback
import psutil
import re
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

# Настройка CustomTkinter
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Настройка логирования
def setup_logging():
    """Настройка системы логирования"""
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            RotatingFileHandler(
                log_dir / 'wexyan.log', 
                maxBytes=5*1024*1024,  # 5MB
                backupCount=3,
                encoding='utf-8'
            ),
            logging.StreamHandler()
        ]
    )
    
    # Устанавливаем уровень для psutil
    logging.getLogger('psutil').setLevel(logging.WARNING)
    
    return logging.getLogger(__name__)

logger = setup_logging()

def is_admin():
    """Проверка прав администратора"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

@dataclass
class ProcessInfo:
    """Информация о процессе"""
    pid: int
    name: str
    username: str
    status: str
    cpu_percent: float
    memory_mb: float
    create_time: float

class ProcessManager:
    """Оптимизированный менеджер процессов"""
    
    def __init__(self):
        self._process_cache = []
        self._cache_time = 0
        self._cache_duration = 2  # секунды
        
    def get_all_processes(self) -> List[ProcessInfo]:
        """Получить все процессы (с кэшированием)"""
        current_time = time.time()
        
        # Используем кэш если он актуален
        if current_time - self._cache_time < self._cache_duration and self._process_cache:
            return self._process_cache.copy()
        
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 
                                           'cpu_percent', 'memory_info', 'create_time']):
                try:
                    info = proc.info
                    memory_mb = info['memory_info'].rss / (1024 * 1024) if info['memory_info'] else 0
                    
                    processes.append(ProcessInfo(
                        pid=info['pid'],
                        name=info['name'],
                        username=info['username'] or 'SYSTEM',
                        status=info['status'],
                        cpu_percent=info['cpu_percent'],
                        memory_mb=round(memory_mb, 1),
                        create_time=info['create_time'] or 0
                    ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            # Сортируем по использованию памяти
            processes.sort(key=lambda x: x.memory_mb, reverse=True)
            
            # Обновляем кэш
            self._process_cache = processes
            self._cache_time = current_time
            
        except Exception as e:
            logger.error(f"Ошибка получения процессов: {e}")
            
        return processes
    
    def search_processes(self, query: str) -> List[ProcessInfo]:
        """Поиск процессов"""
        if not query or not query.strip():
            return self.get_all_processes()
        
        processes = self.get_all_processes()
        query = query.lower().strip()
        
        # Используем list comprehension для оптимизации
        return [
            proc for proc in processes 
            if (query in proc.name.lower() or 
                (query.isdigit() and int(query) == proc.pid) or
                (proc.username and query in proc.username.lower()))
        ]
    
    def kill_process(self, pid: int) -> Tuple[bool, str]:
        """Завершить процесс"""
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            
            # Пробуем мягкое завершение
            proc.terminate()
            time.sleep(0.3)
            
            # Если все еще жив, убиваем
            if proc.is_running():
                proc.kill()
            
            # Инвалидируем кэш
            self._process_cache = []
            
            logger.info(f"Процесс завершен: {proc_name} (PID={pid})")
            return True, f"Процесс {proc_name} завершен"
            
        except psutil.NoSuchProcess:
            return False, "Процесс не найден"
        except psutil.AccessDenied:
            return False, "Нет прав для завершения процесса"
        except Exception as e:
            logger.error(f"Ошибка завершения процесса {pid}: {e}")
            return False, f"Ошибка: {str(e)}"

class ConfigManager:
    """Менеджер конфигурации"""
    
    def __init__(self):
        self.app_data = Path(os.environ.get('APPDATA', Path.home())) / 'WexYanUltimate'
        self.config_path = self.app_data / 'config.json'
        self.ensure_directories()
    
    def ensure_directories(self):
        """Создать необходимые директории"""
        self.app_data.mkdir(parents=True, exist_ok=True)
    
    def load_config(self) -> Dict:
        """Загрузить конфигурацию"""
        default_config = self.get_default_config()
        
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    # Объединяем с дефолтными значениями
                    self._merge_dicts(config, default_config)
                    return config
        except Exception as e:
            logger.error(f"Ошибка загрузки конфигурации: {e}")
        
        return default_config
    
    def save_config(self, config: Dict) -> bool:
        """Сохранить конфигурацию"""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            logger.error(f"Ошибка сохранения конфигурации: {e}")
            return False
    
    def _merge_dicts(self, target: Dict, source: Dict):
        """Рекурсивное объединение словарей"""
        for key, value in source.items():
            if key not in target:
                target[key] = value
            elif isinstance(value, dict) and isinstance(target[key], dict):
                self._merge_dicts(target[key], value)
    
    def get_default_config(self) -> Dict:
        """Конфигурация по умолчанию"""
        return {
            'version': '8.1.0',
            'blocked_apps': [],
            'blocking_active': False,
            'settings': {
                'theme': 'dark',
                'sounds': False,
                'notifications': True,
                'auto_start': False,
                'monitor_interval': 3,
                'start_with_windows': False,
                'minimize_to_tray': True
            },
            'presets': {
                'yandex': ['browser.exe', 'yandex.exe', 'YaBro.exe'],
                'telegram': ['Telegram.exe', 'telegram.exe'],
                'steam': ['steam.exe', 'steamwebhelper.exe'],
                'browser': ['chrome.exe', 'firefox.exe', 'msedge.exe']
            }
        }

class AppBlocker:
    """Блокировщик приложений"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.config = config_manager.load_config()
        self.blocked_apps = self.config.get('blocked_apps', [])
        self.blocking_active = False
        self.monitor_thread = None
        self.stop_event = threading.Event()
        
        # Критические системные процессы
        self.protected_processes = {
            'System', 'System Idle Process', 'svchost.exe', 
            'csrss.exe', 'wininit.exe', 'services.exe',
            'lsass.exe', 'explorer.exe', 'dwm.exe'
        }
    
    def add_app(self, name: str, processes: List[str]) -> str:
        """Добавить приложение для блокировки"""
        app_id = hashlib.md5(f"{name}{datetime.now().timestamp()}".encode()).hexdigest()[:8]
        
        app = {
            'id': app_id,
            'name': name,
            'processes': processes,
            'enabled': True,
            'created': datetime.now().isoformat(),
            'blocks': 0
        }
        
        self.blocked_apps.append(app)
        self._save_config()
        
        logger.info(f"Добавлено приложение для блокировки: {name}")
        return app_id
    
    def remove_app(self, app_id: str) -> bool:
        """Удалить приложение из блокировки"""
        for i, app in enumerate(self.blocked_apps):
            if app['id'] == app_id:
                app_name = app['name']
                del self.blocked_apps[i]
                self._save_config()
                logger.info(f"Удалено приложение из блокировки: {app_name}")
                return True
        return False
    
    def toggle_app(self, app_id: str, enabled: bool) -> bool:
        """Включить/выключить блокировку приложения"""
        for app in self.blocked_apps:
            if app['id'] == app_id:
                app['enabled'] = enabled
                self._save_config()
                status = "включена" if enabled else "отключена"
                logger.info(f"Блокировка {app['name']} {status}")
                return True
        return False
    
    def start_blocking(self):
        """Запустить блокировку"""
        if self.blocking_active:
            return False
        
        self.blocking_active = True
        self.config['blocking_active'] = True
        self._save_config()
        
        self.stop_event.clear()
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info("Блокировка запущена")
        return True
    
    def stop_blocking(self):
        """Остановить блокировку"""
        if not self.blocking_active:
            return False
        
        self.blocking_active = False
        self.config['blocking_active'] = False
        self.stop_event.set()
        
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=1)
        
        self._save_config()
        logger.info("Блокировка остановлена")
        return True
    
    def _monitor_loop(self):
        """Цикл мониторинга"""
        interval = self.config['settings'].get('monitor_interval', 3)
        
        while not self.stop_event.is_set():
            try:
                for app in self.blocked_apps:
                    if not app['enabled']:
                        continue
                    
                    for pattern in app['processes']:
                        self._kill_by_pattern(pattern, app)
                
                time.sleep(interval)
                
            except Exception as e:
                logger.error(f"Ошибка мониторинга: {e}")
                time.sleep(interval * 2)
    
    def _kill_by_pattern(self, pattern: str, app: Dict) -> int:
        """Завершить процессы по шаблону"""
        killed = 0
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info['name']
                    
                    # Пропускаем защищенные процессы
                    if proc_name in self.protected_processes:
                        continue
                    
                    if self._match_pattern(proc_name, pattern):
                        try:
                            proc.kill()
                            killed += 1
                            app['blocks'] = app.get('blocks', 0) + 1
                            logger.debug(f"Заблокирован процесс: {proc_name}")
                        except:
                            continue
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            logger.error(f"Ошибка завершения процессов: {e}")
        
        return killed
    
    def _match_pattern(self, text: str, pattern: str) -> bool:
        """Проверка совпадения с шаблоном"""
        pattern = pattern.strip().lower()
        text = text.lower()
        
        if '*' in pattern:
            regex_pattern = pattern.replace('.', r'\.').replace('*', '.*')
            return bool(re.match(regex_pattern, text))
        else:
            return pattern == text
    
    def block_everything(self) -> Tuple[int, int]:
        """Блокировка всех пользовательских процессов"""
        killed = 0
        skipped = 0
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info['name']
                    proc_pid = proc_info['pid']
                    
                    # Пропускаем защищенные процессы
                    if proc_name in self.protected_processes:
                        skipped += 1
                        continue
                    
                    # Пропускаем текущий процесс Python
                    if proc_pid == os.getpid():
                        skipped += 1
                        continue
                    
                    try:
                        proc.kill()
                        killed += 1
                        logger.warning(f"Заблокирован процесс: {proc_name} (PID: {proc_pid})")
                    except:
                        skipped += 1
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            logger.error(f"Ошибка при блокировке всего: {e}")
        
        return killed, skipped
    
    def _save_config(self):
        """Сохранить конфигурацию"""
        self.config['blocked_apps'] = self.blocked_apps
        self.config_manager.save_config(self.config)

class ModernUI(ctk.CTk):
    """Современный интерфейс приложения"""
    
    def __init__(self):
        # Проверка прав администратора
        if not is_admin():
            self._request_admin()
        
        super().__init__()
        
        # Инициализация компонентов
        self.process_manager = ProcessManager()
        self.config_manager = ConfigManager()
        self.blocker = AppBlocker(self.config_manager)
        
        # Инициализация переменных UI
        self.stats_label = None
        self.uptime_label = None
        self.status_label = None
        self.protection_btn = None
        self.notify_var = None
        self.sounds_var = None
        self.interval_var = None
        self.interval_label = None
        self.search_var = None
        self.tree = None
        self.apps_container = None
        self.tabview = None
        
        # Настройка окна
        self._setup_window()
        
        # Создание интерфейса
        self._create_widgets()
        
        # Запуск обновлений
        self._start_updates()
        
        logger.info("Приложение запущено")
    
    def _request_admin(self):
        """Запрос прав администратора"""
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
        except Exception as e:
            messagebox.showerror(
                "Требуются права администратора",
                "Запустите приложение от имени администратора"
            )
        finally:
            sys.exit(1)
    
    def _setup_window(self):
        """Настройка главного окна"""
        self.title("WexYan Ultimate v8.1")
        self.geometry("1200x700")
        self.minsize(1000, 600)
        
        # Иконка приложения
        try:
            self.iconbitmap('icon.ico')
        except:
            pass
        
        # Центрирование окна
        self.update_idletasks()
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width - self.winfo_width()) // 2
        y = (screen_height - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")
        
        # Обработчик закрытия
        self.protocol("WM_DELETE_WINDOW", self._on_closing)
    
    def _create_widgets(self):
        """Создание виджетов интерфейса"""
        # Создаем сетку
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        
        # Боковая панель
        self._create_sidebar()
        
        # Основная область
        self._create_main_area()
        
        # Статус бар
        self._create_statusbar()
    
    def _create_sidebar(self):
        """Создание боковой панели"""
        sidebar = ctk.CTkFrame(self, width=250, corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        
        # Логотип
        logo_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        logo_frame.pack(pady=20, padx=20, fill="x")
        
        ctk.CTkLabel(
            logo_frame,
            text="🛡️ WEXYAN",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#3b82f6"
        ).pack()
        
        ctk.CTkLabel(
            logo_frame,
            text="ULTIMATE v8.1",
            font=ctk.CTkFont(size=12),
            text_color="#94a3b8"
        ).pack()
        
        # Поиск
        search_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        search_frame.pack(pady=10, padx=20, fill="x")
        
        self.search_var = tk.StringVar()
        search_entry = ctk.CTkEntry(
            search_frame,
            textvariable=self.search_var,
            placeholder_text="Поиск процессов...",
            height=35
        )
        search_entry.pack(fill="x")
        search_entry.bind("<Return>", lambda e: self._search_processes())
        
        ctk.CTkButton(
            search_frame,
            text="Найти",
            command=self._search_processes,
            height=35
        ).pack(fill="x", pady=(5, 0))
        
        # Быстрые действия
        actions_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        actions_frame.pack(pady=20, padx=20, fill="x")
        
        ctk.CTkLabel(
            actions_frame,
            text="Быстрые действия",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", pady=(0, 10))
        
        # Кнопка защиты
        self.protection_btn = ctk.CTkButton(
            actions_frame,
            text="▶ Запустить защиту",
            command=self._toggle_protection,
            fg_color="#10b981",
            hover_color="#059669",
            height=40
        )
        self.protection_btn.pack(fill="x", pady=5)
        
        # Кнопка обновления списка
        ctk.CTkButton(
            actions_frame,
            text="🔄 Обновить список",
            command=self._refresh_processes,
            height=40
        ).pack(fill="x", pady=5)
        
        # Быстрые блокировки
        presets_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        presets_frame.pack(pady=10, padx=20, fill="x")
        
        ctk.CTkLabel(
            presets_frame,
            text="Быстрые блокировки",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", pady=(0, 10))
        
        presets = [
            ("🔍 Яндекс", "yandex"),
            ("📱 Telegram", "telegram"),
            ("🎮 Steam", "steam"),
            ("🌐 Браузеры", "browser")
        ]
        
        for text, preset in presets:
            btn = ctk.CTkButton(
                presets_frame,
                text=text,
                command=lambda p=preset: self._block_preset(p),
                height=35,
                fg_color="#475569",
                hover_color="#64748b"
            )
            btn.pack(fill="x", pady=2)
        
        # Опасная зона
        danger_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        danger_frame.pack(pady=20, padx=20, fill="x")
        
        ctk.CTkLabel(
            danger_frame,
            text="⚠️ Опасные действия",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#ef4444"
        ).pack(anchor="w", pady=(0, 10))
        
        ctk.CTkButton(
            danger_frame,
            text="☠️ БЛОКИРОВКА ВСЕГО",
            command=self._show_block_everything_warning,
            fg_color="#dc2626",
            hover_color="#b91c1c",
            height=40
        ).pack(fill="x")
        
        warning_text = """ВНИМАНИЕ: Эта функция
заблокирует ВСЕ процессы!
Создатель не несет
ответственности."""
        
        ctk.CTkLabel(
            danger_frame,
            text=warning_text,
            font=ctk.CTkFont(size=10),
            text_color="#f59e0b",
            justify="center"
        ).pack(pady=5)
    
    def _create_main_area(self):
        """Создание основной области"""
        main_frame = ctk.CTkFrame(self, corner_radius=0)
        main_frame.grid(row=0, column=1, sticky="nsew", padx=2, pady=2)
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        
        # Вкладки
        self.tabview = ctk.CTkTabview(main_frame)
        self.tabview.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        # Добавляем вкладки
        self.tabview.add("Процессы")
        self.tabview.add("Заблокированные")
        self.tabview.add("Настройки")
        
        # Создаем содержимое вкладок
        self._create_processes_tab()
        self._create_blocked_tab()
        self._create_settings_tab()
    
    def _create_processes_tab(self):
        """Вкладка процессов"""
        tab = self.tabview.tab("Процессы")
        
        # Панель инструментов
        toolbar = ctk.CTkFrame(tab, height=50)
        toolbar.pack(fill="x", padx=10, pady=(10, 0))
        toolbar.pack_propagate(False)
        
        ctk.CTkLabel(
            toolbar,
            text="📋 Запущенные процессы",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(side="left", padx=15)
        
        # Таблица процессов
        table_frame = ctk.CTkFrame(tab)
        table_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Создаем Treeview
        columns = ('PID', 'Имя', 'CPU %', 'Память (MB)', 'Пользователь', 'Статус')
        self.tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=20)
        
        # Настраиваем столбцы
        col_widths = [80, 250, 80, 100, 150, 100]
        for col, width in zip(columns, col_widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor='center')
        
        # Полоса прокрутки
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Упаковка
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Привязка событий
        self.tree.bind("<Double-1>", self._on_process_double_click)
        self.tree.bind("<Button-3>", self._show_process_menu)
        
        # Загружаем процессы
        self._load_processes()
    
    def _create_blocked_tab(self):
        """Вкладка заблокированных приложений"""
        tab = self.tabview.tab("Заблокированные")
        
        # Панель инструментов
        toolbar = ctk.CTkFrame(tab, height=50)
        toolbar.pack(fill="x", padx=10, pady=(10, 0))
        toolbar.pack_propagate(False)
        
        ctk.CTkLabel(
            toolbar,
            text="🛡️ Заблокированные приложения",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(side="left", padx=15)
        
        ctk.CTkButton(
            toolbar,
            text="➕ Добавить",
            command=self._show_add_app_dialog,
            width=100,
            height=30
        ).pack(side="right", padx=15)
        
        # Контейнер для карточек
        self.apps_container = ctk.CTkScrollableFrame(tab)
        self.apps_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Загружаем приложения
        self._load_blocked_apps()
    
    def _create_settings_tab(self):
        """Вкладка настроек"""
        tab = self.tabview.tab("Настройки")
        
        # Основной контейнер
        container = ctk.CTkScrollableFrame(tab)
        container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Общие настройки
        ctk.CTkLabel(
            container,
            text="⚙️ Общие настройки",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(anchor="w", pady=(0, 20))
        
        # Уведомления
        self.notify_var = tk.BooleanVar(value=True)
        ctk.CTkSwitch(
            container,
            text="Показывать уведомления",
            variable=self.notify_var,
            font=ctk.CTkFont(size=14)
        ).pack(anchor="w", pady=5)
        
        # Звуки
        self.sounds_var = tk.BooleanVar(value=False)
        ctk.CTkSwitch(
            container,
            text="Воспроизводить звуки",
            variable=self.sounds_var,
            font=ctk.CTkFont(size=14)
        ).pack(anchor="w", pady=5)
        
        # Интервал проверки
        interval_frame = ctk.CTkFrame(container, fg_color="transparent")
        interval_frame.pack(fill="x", pady=20)
        
        ctk.CTkLabel(
            interval_frame,
            text="Интервал проверки:",
            font=ctk.CTkFont(size=14)
        ).pack(anchor="w")
        
        self.interval_var = tk.IntVar(value=3)
        interval_slider = ctk.CTkSlider(
            interval_frame,
            from_=1,
            to=10,
            variable=self.interval_var,
            number_of_steps=9,
            width=300
        )
        interval_slider.pack(anchor="w", pady=(5, 0))
        
        self.interval_label = ctk.CTkLabel(
            interval_frame,
            text="3 секунды",
            font=ctk.CTkFont(size=12),
            text_color="#94a3b8"
        )
        self.interval_label.pack(anchor="w")
        
        interval_slider.configure(command=self._update_interval_label)
        
        # Кнопки управления
        btn_frame = ctk.CTkFrame(container, fg_color="transparent")
        btn_frame.pack(pady=30)
        
        ctk.CTkButton(
            btn_frame,
            text="💾 Сохранить",
            command=self._save_settings,
            width=150,
            height=40
        ).pack(side="left", padx=10)
        
        ctk.CTkButton(
            btn_frame,
            text="🔄 Сбросить",
            command=self._reset_settings,
            width=150,
            height=40,
            fg_color="#475569",
            hover_color="#64748b"
        ).pack(side="left", padx=10)
    
    def _create_statusbar(self):
        """Создание статус бара"""
        statusbar = ctk.CTkFrame(self, height=30)
        statusbar.grid(row=1, column=0, columnspan=2, sticky="ew", padx=2, pady=(0, 2))
        statusbar.grid_propagate(False)
        
        # Статус защиты
        self.status_label = ctk.CTkLabel(
            statusbar,
            text="Защита: ❌ Выключена",
            font=ctk.CTkFont(size=11),
            text_color="#ef4444"
        )
        self.status_label.pack(side="left", padx=15)
        
        # Статистика
        self.stats_label = ctk.CTkLabel(
            statusbar,
            text="Процессов: 0 | Заблокировано: 0",
            font=ctk.CTkFont(size=11),
            text_color="#94a3b8"
        )
        self.stats_label.pack(side="left", padx=15)
        
        # Время работы
        self.start_time = time.time()
        self.uptime_label = ctk.CTkLabel(
            statusbar,
            text="Время работы: 00:00:00",
            font=ctk.CTkFont(size=11),
            text_color="#94a3b8"
        )
        self.uptime_label.pack(side="right", padx=15)
        
        # Обновляем статус защиты
        self._update_protection_status()
    
    def _load_processes(self, query: str = ""):
        """Загрузить процессы в таблицу"""
        # Проверяем, создана ли таблица
        if not hasattr(self, 'tree') or self.tree is None:
            return
        
        # Очищаем таблицу
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Получаем процессы
        processes = self.process_manager.search_processes(query)
        
        # Заполняем таблицу
        for proc in processes:
            self.tree.insert('', 'end', values=(
                proc.pid,
                proc.name,
                f"{proc.cpu_percent:.1f}",
                f"{proc.memory_mb:.1f}",
                proc.username[:20] if proc.username else "SYSTEM",
                proc.status
            ))
        
        # Обновляем статистику
        self._update_stats()
    
    def _load_blocked_apps(self):
        """Загрузить заблокированные приложения"""
        # Проверяем, создан ли контейнер
        if not hasattr(self, 'apps_container') or self.apps_container is None:
            return
        
        # Очищаем контейнер
        for widget in self.apps_container.winfo_children():
            widget.destroy()
        
        if not self.blocker.blocked_apps:
            # Сообщение если нет приложений
            ctk.CTkLabel(
                self.apps_container,
                text="Нет заблокированных приложений",
                font=ctk.CTkFont(size=14),
                text_color="#94a3b8"
            ).pack(pady=50)
            return
        
        # Создаем карточки
        for app in self.blocker.blocked_apps:
            self._create_app_card(app)
    
    def _create_app_card(self, app: Dict):
        """Создать карточку приложения"""
        card = ctk.CTkFrame(self.apps_container, corner_radius=10)
        card.pack(fill="x", pady=5, padx=5)
        
        # Верхняя часть
        top_frame = ctk.CTkFrame(card, fg_color="transparent")
        top_frame.pack(fill="x", padx=15, pady=(10, 5))
        
        ctk.CTkLabel(
            top_frame,
            text=app['name'],
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(side="left")
        
        # Статус
        status_color = "#10b981" if app['enabled'] else "#94a3b8"
        status_text = "✅ Активно" if app['enabled'] else "⏸️ Отключено"
        
        ctk.CTkLabel(
            top_frame,
            text=status_text,
            font=ctk.CTkFont(size=12),
            text_color=status_color
        ).pack(side="right")
        
        # Процессы
        mid_frame = ctk.CTkFrame(card, fg_color="transparent")
        mid_frame.pack(fill="x", padx=15, pady=5)
        
        processes_text = ", ".join(app['processes'][:3])
        if len(app['processes']) > 3:
            processes_text += f" (+{len(app['processes']) - 3})"
        
        ctk.CTkLabel(
            mid_frame,
            text=f"Процессы: {processes_text}",
            font=ctk.CTkFont(size=12),
            text_color="#cbd5e1"
        ).pack(anchor="w")
        
        # Кнопки
        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.pack(fill="x", padx=15, pady=(5, 10))
        
        # Кнопка переключения
        toggle_text = "⏸️ Отключить" if app['enabled'] else "▶️ Включить"
        toggle_color = "#f59e0b" if app['enabled'] else "#10b981"
        
        ctk.CTkButton(
            btn_frame,
            text=toggle_text,
            command=lambda a=app: self._toggle_app_blocking(a),
            width=100,
            height=30,
            fg_color=toggle_color,
            hover_color=toggle_color
        ).pack(side="left", padx=(0, 10))
        
        # Кнопка удаления
        ctk.CTkButton(
            btn_frame,
            text="🗑️ Удалить",
            command=lambda a=app: self._confirm_remove_app(a),
            width=100,
            height=30,
            fg_color="#dc2626",
            hover_color="#b91c1c"
        ).pack(side="left")
    
    def _search_processes(self):
        """Поиск процессов"""
        query = self.search_var.get()
        self._load_processes(query)
    
    def _refresh_processes(self):
        """Обновить список процессов"""
        self._load_processes(self.search_var.get())
        self._show_notification("Список обновлен", "info")
    
    def _on_process_double_click(self, event):
        """Обработка двойного клика по процессу"""
        selection = self.tree.selection()
        if not selection:
            return
        
        item = self.tree.item(selection[0])
        pid = int(item['values'][0])
        name = item['values'][1]
        
        self._show_process_dialog(pid, name)
    
    def _show_process_menu(self, event):
        """Контекстное меню для процесса"""
        selection = self.tree.identify_row(event.y)
        if not selection:
            return
        
        self.tree.selection_set(selection)
        item = self.tree.item(selection)
        pid = int(item['values'][0])
        name = item['values'][1]
        
        # Создаем меню
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label=f"Завершить {name}", 
                        command=lambda: self._kill_process(pid, name))
        menu.add_command(label="Добавить в блокировку", 
                        command=lambda: self._add_to_blocking(name))
        menu.add_separator()
        menu.add_command(label="Отмена", command=menu.destroy)
        
        # Показываем меню
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()
    
    def _show_process_dialog(self, pid: int, name: str):
        """Диалог действий с процессом"""
        dialog = ctk.CTkToplevel(self)
        dialog.title(f"Действия: {name}")
        dialog.geometry("400x300")
        dialog.transient(self)
        dialog.grab_set()
        
        ctk.CTkLabel(
            dialog,
            text=f"Процесс: {name}",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=20)
        
        ctk.CTkLabel(
            dialog,
            text=f"PID: {pid}",
            font=ctk.CTkFont(size=14)
        ).pack(pady=5)
        
        # Кнопки действий
        ctk.CTkButton(
            dialog,
            text="🚫 Завершить процесс",
            command=lambda: [self._kill_process(pid, name), dialog.destroy()],
            height=40,
            fg_color="#dc2626",
            hover_color="#b91c1c"
        ).pack(pady=10, padx=50, fill="x")
        
        ctk.CTkButton(
            dialog,
            text="🛡️ Добавить в блокировку",
            command=lambda: [self._add_to_blocking(name), dialog.destroy()],
            height=40
        ).pack(pady=10, padx=50, fill="x")
        
        ctk.CTkButton(
            dialog,
            text="✕ Закрыть",
            command=dialog.destroy,
            height=40,
            fg_color="#475569",
            hover_color="#64748b"
        ).pack(pady=10, padx=50, fill="x")
        
        # Центрируем диалог
        self._center_dialog(dialog)
    
    def _kill_process(self, pid: int, name: str):
        """Завершить процесс"""
        success, message = self.process_manager.kill_process(pid)
        
        if success:
            self._show_notification(f"Процесс '{name}' завершен", "success")
            self._refresh_processes()
        else:
            self._show_notification(message, "error")
    
    def _add_to_blocking(self, process_name: str):
        """Добавить процесс в блокировку"""
        dialog = ctk.CTkToplevel(self)
        dialog.title("Добавить в блокировку")
        dialog.geometry("400x250")
        dialog.transient(self)
        dialog.grab_set()
        
        ctk.CTkLabel(
            dialog,
            text="Добавить приложение",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=20)
        
        # Название
        name_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        name_frame.pack(pady=10, padx=20, fill="x")
        
        ctk.CTkLabel(name_frame, text="Название:").pack(anchor="w")
        name_entry = ctk.CTkEntry(name_frame)
        name_entry.pack(fill="x", pady=(5, 0))
        name_entry.insert(0, process_name.split('.')[0].title())
        
        # Процессы
        proc_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        proc_frame.pack(pady=10, padx=20, fill="x")
        
        ctk.CTkLabel(proc_frame, text="Процессы:").pack(anchor="w")
        proc_entry = ctk.CTkEntry(proc_frame)
        proc_entry.pack(fill="x", pady=(5, 0))
        proc_entry.insert(0, process_name)
        
        def add():
            app_name = name_entry.get().strip()
            processes = [p.strip() for p in proc_entry.get().split(',') if p.strip()]
            
            if not app_name or not processes:
                self._show_notification("Заполните все поля", "error")
                return
            
            self.blocker.add_app(app_name, processes)
            self._load_blocked_apps()
            dialog.destroy()
            self._show_notification(f"Приложение '{app_name}' добавлено", "success")
        
        # Кнопки
        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        btn_frame.pack(pady=20, padx=20, fill="x")
        
        ctk.CTkButton(
            btn_frame,
            text="Добавить",
            command=add,
            height=35
        ).pack(side="left", padx=(0, 10), expand=True)
        
        ctk.CTkButton(
            btn_frame,
            text="Отмена",
            command=dialog.destroy,
            height=35,
            fg_color="#475569",
            hover_color="#64748b"
        ).pack(side="left", expand=True)
        
        self._center_dialog(dialog)
    
    def _show_add_app_dialog(self):
        """Показать диалог добавления приложения"""
        self._add_to_blocking("")
    
    def _toggle_app_blocking(self, app: Dict):
        """Включить/выключить блокировку приложения"""
        self.blocker.toggle_app(app['id'], not app['enabled'])
        self._load_blocked_apps()
        
        status = "включена" if not app['enabled'] else "отключена"
        self._show_notification(f"Блокировка '{app['name']}' {status}", "info")
    
    def _confirm_remove_app(self, app: Dict):
        """Подтверждение удаления приложения"""
        result = messagebox.askyesno(
            "Подтверждение",
            f"Удалить приложение '{app['name']}' из списка блокировки?"
        )
        
        if result:
            self.blocker.remove_app(app['id'])
            self._load_blocked_apps()
            self._show_notification(f"Приложение '{app['name']}' удалено", "info")
    
    def _block_preset(self, preset_name: str):
        """Блокировать по пресету"""
        if preset_name in self.blocker.config.get('presets', {}):
            processes = self.blocker.config['presets'][preset_name]
            app_name = preset_name.capitalize()
            
            self.blocker.add_app(app_name, processes)
            self._load_blocked_apps()
            
            self._show_notification(f"Пресет '{app_name}' активирован", "success")
    
    def _toggle_protection(self):
        """Включить/выключить защиту"""
        if self.blocker.blocking_active:
            self.blocker.stop_blocking()
            self.protection_btn.configure(
                text="▶ Запустить защиту",
                fg_color="#10b981",
                hover_color="#059669"
            )
        else:
            self.blocker.start_blocking()
            self.protection_btn.configure(
                text="⏸ Остановить защиту",
                fg_color="#ef4444",
                hover_color="#dc2626"
            )
        
        self._update_protection_status()
    
    def _update_protection_status(self):
        """Обновить статус защиты"""
        if not hasattr(self, 'status_label') or self.status_label is None:
            return
            
        if self.blocker.blocking_active:
            self.status_label.configure(
                text="Защита: ✅ Активна",
                text_color="#10b981"
            )
        else:
            self.status_label.configure(
                text="Защита: ❌ Выключена",
                text_color="#ef4444"
            )
    
    def _show_block_everything_warning(self):
        """Показать предупреждение о блокировке всего"""
        warning_text = """
ВНИМАНИЕ! ОПАСНАЯ ФУНКЦИЯ!

Эта функция завершит ВСЕ пользовательские процессы.

Последствия:
• Все приложения будут закрыты
• Несохраненные данные будут потеряны
• Система может стать нестабильной

Создатель данного ПО НЕ несет ответственности
за любые повреждения вашего компьютера.

Вы уверены, что хотите продолжить?
"""
        
        result = messagebox.askyesno(
            "КРИТИЧЕСКОЕ ПРЕДУПРЕЖДЕНИЕ",
            warning_text,
            icon='warning'
        )
        
        if result:
            # Финальное подтверждение
            result2 = messagebox.askyesno(
                "Последний шанс",
                "Вы точно уверены? Это действие невозможно отменить!"
            )
            
            if result2:
                self._block_everything()
    
    def _block_everything(self):
        """Блокировать все процессы"""
        self._show_notification("Начата блокировка всех процессов...", "warning")
        
        # Запускаем в отдельном потоке
        def blocking_thread():
            killed, skipped = self.blocker.block_everything()
            
            self.after(0, lambda: self._show_notification(
                f"Заблокировано процессов: {killed}, пропущено: {skipped}",
                "info"
            ))
            self.after(0, self._refresh_processes)
        
        threading.Thread(target=blocking_thread, daemon=True).start()
    
    def _save_settings(self):
        """Сохранить настройки"""
        config = self.blocker.config
        config['settings']['notifications'] = self.notify_var.get()
        config['settings']['sounds'] = self.sounds_var.get()
        config['settings']['monitor_interval'] = self.interval_var.get()
        
        if self.config_manager.save_config(config):
            self._show_notification("Настройки сохранены", "success")
        else:
            self._show_notification("Ошибка сохранения настроек", "error")
    
    def _reset_settings(self):
        """Сбросить настройки"""
        result = messagebox.askyesno(
            "Сброс настроек",
            "Сбросить все настройки к значениям по умолчанию?"
        )
        
        if result:
            # Создаем новую конфигурацию
            self.blocker.config = self.config_manager.get_default_config()
            self.blocker.blocked_apps = []
            self.blocker._save_config()
            
            # Обновляем интерфейс
            self._load_blocked_apps()
            self._update_protection_status()
            
            self._show_notification("Настройки сброшены", "info")
    
    def _update_interval_label(self, value):
        """Обновить метку интервала"""
        if hasattr(self, 'interval_label') and self.interval_label is not None:
            self.interval_label.configure(text=f"{int(float(value))} секунд")
    
    def _update_stats(self):
        """Обновить статистику"""
        if not hasattr(self, 'stats_label') or self.stats_label is None:
            return
            
        processes = self.process_manager.get_all_processes()
        total_blocks = sum(app.get('blocks', 0) for app in self.blocker.blocked_apps)
        
        self.stats_label.configure(
            text=f"Процессов: {len(processes)} | Заблокировано: {total_blocks}"
        )
    
    def _show_notification(self, message: str, ntype: str = "info"):
        """Показать уведомление"""
        if not hasattr(self, 'notify_var') or not self.notify_var.get():
            return
        
        # Цвета для разных типов
        colors = {
            "success": "#10b981",
            "error": "#ef4444",
            "warning": "#f59e0b",
            "info": "#3b82f6"
        }
        
        color = colors.get(ntype, "#3b82f6")
        
        # Создаем уведомление
        notification = ctk.CTkFrame(self, corner_radius=10)
        notification.configure(fg_color=color, border_width=2, border_color=color)
        
        # Текст уведомления
        ctk.CTkLabel(
            notification,
            text=message,
            font=ctk.CTkFont(size=12),
            text_color="#ffffff",
            wraplength=300
        ).pack(padx=20, pady=15)
        
        # Позиционируем
        notification.place(relx=0.02, rely=0.02, anchor="nw")
        
        # Автоудаление через 3 секунды
        def remove():
            try:
                notification.destroy()
            except:
                pass
        
        self.after(3000, remove)
        
        # Логируем
        logger.info(f"Уведомление: {message}")
    
    def _center_dialog(self, dialog):
        """Центрировать диалоговое окно"""
        dialog.update_idletasks()
        width = dialog.winfo_width()
        height = dialog.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        dialog.geometry(f'{width}x{height}+{x}+{y}')
    
    def _start_updates(self):
        """Запустить периодические обновления"""
        # Небольшая задержка перед первым обновлением, чтобы UI успел создать все элементы
        self.after(100, self._update_ui)
    
    def _update_ui(self):
        """Обновление интерфейса"""
        try:
            # Обновляем время работы
            if hasattr(self, 'uptime_label') and self.uptime_label is not None:
                uptime = int(time.time() - self.start_time)
                hours = uptime // 3600
                minutes = (uptime % 3600) // 60
                seconds = uptime % 60
                self.uptime_label.configure(
                    text=f"Время работы: {hours:02d}:{minutes:02d}:{seconds:02d}"
                )
                
                # Обновляем статистику каждые 5 секунд
                if uptime % 5 == 0:
                    self._update_stats()
            
        except Exception as e:
            logger.error(f"Ошибка обновления UI: {e}")
        
        # Следующее обновление через 1 секунду
        self.after(1000, self._update_ui)
    
    def _on_closing(self):
        """Обработчик закрытия окна"""
        if self.blocker.blocking_active:
            self.blocker.stop_blocking()
        
        self.destroy()
        logger.info("Приложение закрыто")

def main():
    """Главная функция"""
    try:
        # Проверяем зависимости
        try:
            import psutil
        except ImportError:
            print("❌ Установите psutil: pip install psutil")
            input("Нажмите Enter для выхода...")
            return
        
        try:
            import customtkinter
        except ImportError:
            print("❌ Установите customtkinter: pip install customtkinter")
            input("Нажмите Enter для выхода...")
            return
        
        # Запускаем приложение
        app = ModernUI()
        app.mainloop()
        
    except Exception as e:
        logger.critical(f"Критическая ошибка: {e}", exc_info=True)
        messagebox.showerror(
            "Критическая ошибка",
            f"Произошла ошибка:\n\n{str(e)}\n\nПодробности в лог-файле."
        )

if __name__ == "__main__":
    main()