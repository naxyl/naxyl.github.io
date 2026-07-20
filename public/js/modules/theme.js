(() => {
  var __defProp = Object.defineProperty;
  var __typeError = (msg) => {
    throw TypeError(msg);
  };
  var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
  var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);
  var __accessCheck = (obj, member, msg) => member.has(obj) || __typeError("Cannot " + msg);
  var __privateGet = (obj, member, getter) => (__accessCheck(obj, member, "read from private field"), getter ? getter.call(obj) : member.get(obj));
  var __privateAdd = (obj, member, value) => member.has(obj) ? __typeError("Cannot add the same private member more than once") : member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
  var __privateMethod = (obj, member, method) => (__accessCheck(obj, member, "access private method"), method);

  // <stdin>
  var _modeKey, _modeAttr, _darkMedia, _Theme_static, mode_get, isDarkMode_get, hasMode_get, sysDark_get, setDark_fn, setLight_fn, clearMode_fn, notify_fn;
  var _Theme = class _Theme {
    static get DARK() {
      return "dark";
    }
    static get LIGHT() {
      return "light";
    }
    /**
     * @returns {string} Theme mode identifier
     */
    static get ID() {
      return "theme-mode";
    }
    /**
     * Gets the current visual state of the theme.
     *
     * @returns {string} The current visual state, either the mode if it exists,
     *                   or the system dark mode state ('dark' or 'light').
     */
    static get visualState() {
      if (__privateGet(this, _Theme_static, hasMode_get)) {
        return __privateGet(this, _Theme_static, mode_get);
      } else {
        return __privateGet(this, _Theme_static, sysDark_get) ? this.DARK : this.LIGHT;
      }
    }
    /**
     * Maps theme modes to provided values
     * @param {string} light Value for light mode
     * @param {string} dark Value for dark mode
     * @returns {Object} Mapped values
     */
    static getThemeMapper(light, dark) {
      return {
        [this.LIGHT]: light,
        [this.DARK]: dark
      };
    }
    /**
     * Initializes the theme based on system preferences or stored mode
     */
    static init() {
      if (!this.switchable) {
        return;
      }
      __privateGet(this, _darkMedia).addEventListener("change", () => {
        const lastMode = __privateGet(this, _Theme_static, mode_get);
        __privateMethod(this, _Theme_static, clearMode_fn).call(this);
        if (lastMode !== this.visualState) {
          __privateMethod(this, _Theme_static, notify_fn).call(this);
        }
      });
      if (!__privateGet(this, _Theme_static, hasMode_get)) {
        return;
      }
      if (__privateGet(this, _Theme_static, isDarkMode_get)) {
        __privateMethod(this, _Theme_static, setDark_fn).call(this);
      } else {
        __privateMethod(this, _Theme_static, setLight_fn).call(this);
      }
    }
    /**
     * Flips the current theme mode
     */
    static flip() {
      if (__privateGet(this, _Theme_static, hasMode_get)) {
        __privateMethod(this, _Theme_static, clearMode_fn).call(this);
      } else {
        __privateGet(this, _Theme_static, sysDark_get) ? __privateMethod(this, _Theme_static, setLight_fn).call(this) : __privateMethod(this, _Theme_static, setDark_fn).call(this);
      }
      __privateMethod(this, _Theme_static, notify_fn).call(this);
    }
  };
  _modeKey = new WeakMap();
  _modeAttr = new WeakMap();
  _darkMedia = new WeakMap();
  _Theme_static = new WeakSet();
  mode_get = function() {
    return sessionStorage.getItem(__privateGet(this, _modeKey)) || document.documentElement.getAttribute(__privateGet(this, _modeAttr));
  };
  isDarkMode_get = function() {
    return __privateGet(this, _Theme_static, mode_get) === this.DARK;
  };
  hasMode_get = function() {
    return __privateGet(this, _Theme_static, mode_get) !== null;
  };
  sysDark_get = function() {
    return __privateGet(this, _darkMedia).matches;
  };
  setDark_fn = function() {
    document.documentElement.setAttribute(__privateGet(this, _modeAttr), this.DARK);
    sessionStorage.setItem(__privateGet(this, _modeKey), this.DARK);
  };
  setLight_fn = function() {
    document.documentElement.setAttribute(__privateGet(this, _modeAttr), this.LIGHT);
    sessionStorage.setItem(__privateGet(this, _modeKey), this.LIGHT);
  };
  clearMode_fn = function() {
    document.documentElement.removeAttribute(__privateGet(this, _modeAttr));
    sessionStorage.removeItem(__privateGet(this, _modeKey));
  };
  notify_fn = function() {
    window.postMessage({ id: this.ID }, "*");
  };
  __privateAdd(_Theme, _Theme_static);
  __privateAdd(_Theme, _modeKey, "mode");
  __privateAdd(_Theme, _modeAttr, "data-mode");
  __privateAdd(_Theme, _darkMedia, window.matchMedia("(prefers-color-scheme: dark)"));
  __publicField(_Theme, "switchable", !document.documentElement.hasAttribute(__privateGet(_Theme, _modeAttr)));
  var Theme = _Theme;
  Theme.init();
  var stdin_default = Theme;
  window.Theme = Theme;
})();
