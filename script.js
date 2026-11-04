const openAuthButton = document.querySelector('#open-auth');
const userPanel = document.querySelector('#user-panel');
const usernameLabel = document.querySelector('#username-label');
const titleInput = document.querySelector('#task-title');
const descriptionInput = document.querySelector('#task-description');
const addTaskButton = document.querySelector('#add-task');
const logoutButton = document.querySelector('#logout');
const taskList = document.querySelector('#task-list');
const formError = document.querySelector('#form-error');

let authOverlay;
let authError;

function closeAuthWindow() {
  if (!authOverlay) return;

  authOverlay.remove();
  authOverlay = null;
  authError = null;
  Array.from(document.body.children).forEach((child) => { child.inert = false; });
  document.body.classList.remove('auth-locked');
  if (!userPanel.hidden) {
    logoutButton.focus();
  } else {
    openAuthButton.focus();
  }
}

function createAuthWindow() {
  if (authOverlay) return;
  authOverlay = document.createElement('div');
  authOverlay.className = 'auth-overlay';
  authOverlay.innerHTML = `
    <section class="auth-window" role="dialog" aria-modal="true" aria-labelledby="auth-title">
      <div class="auth-heading">
        <h2 id="auth-title">Вход или регистрация</h2>
        <button class="auth-close" type="button" aria-label="Закрыть окно">×</button>
      </div>
      <input id="auth-username" type="text" placeholder="Логин" autocomplete="username">
      <input id="auth-password" type="password" placeholder="Пароль" autocomplete="current-password">
      <div class="auth-actions">
        <button id="login" type="button">Авторизация</button>
        <button id="register" type="button">Регистрация</button>
      </div>
      <p id="auth-error" role="alert"></p>
    </section>
  `;
  document.body.append(authOverlay);

  authUsernameInput = authOverlay.querySelector('#auth-username');
  authPasswordInput = authOverlay.querySelector('#auth-password');
  authError = authOverlay.querySelector('#auth-error');
  authOverlay.querySelector('.auth-close').addEventListener('click', closeAuthWindow);
  authOverlay.querySelector('#login').addEventListener('click', () => {
    authenticate('/api/auth/login');
  });
  authOverlay.querySelector('#register').addEventListener('click', () => {
    authenticate('/api/auth/register');
  });
  authOverlay.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      closeAuthWindow();
    }
    if (event.key === 'Tab') {
      const focusable = authOverlay.querySelectorAll('input, button');
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
  });
  authOverlay.addEventListener('click', (event) => {
    if (event.target === authOverlay) closeAuthWindow();
  });
  Array.from(document.body.children).forEach((child) => {
    if (child !== authOverlay) child.inert = true;
  });
  document.body.classList.add('auth-locked');
  authUsernameInput.focus();
}

async function requestJson(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    }
  });
  const result = await response.json();

  if (!response.ok) {
    const error = new Error(result.error || 'Ошибка запроса.');
    error.status = response.status;
    throw error;
  }

  return result;
}

function setAuthenticatedUser(user) {
  userPanel.hidden = !user;
  openAuthButton.hidden = Boolean(user);
  usernameLabel.textContent = user ? `Вы вошли как ${user.username}` : '';
  if (user) {
    closeAuthWindow();
  }
  if (!user) {
    taskList.replaceChildren();
  }
}

openAuthButton.addEventListener('click', createAuthWindow);

async function loadTasks() {
  const tasks = await requestJson('/api/tasks');
  taskList.replaceChildren();

  tasks.forEach((task) => {
    const item = document.createElement('li');
    const title = document.createElement('span');
    const details = document.createElement('span')

    title.textContent = task.title;
    details.textContent = task.details;

    const deleteButton = document.createElement('button');
    deleteButton.type = 'button';
    deleteButton.textContent = 'Удалить';
    deleteButton.addEventListener('click', () => deleteTask(task.id));

    title.addEventListener('click', ()=>{
      if(details.hidden == false && deleteButton.hidden == false)
      {
        details.hidden = true;
        deleteButton.hidden = true
      }
      else if(details.hidden == true && deleteButton.hidden == true)
      {
        details.hidden = false;
        deleteButton.hidden = false;
      }
    })

    details.hidden = true;
    deleteButton.hidden = true;

    item.append(title, details, deleteButton);
    taskList.append(item);
  });
}

async function authenticate(endpoint) {
  authError.textContent = '';
  try {
    const { user } = await requestJson(endpoint, {
      method: 'POST',
      body: JSON.stringify({
        username: authUsernameInput.value.trim(),
        password: authPasswordInput.value
      })
    });
    setAuthenticatedUser(user);
    authPasswordInput.value = '';
    await loadTasks();
  } catch (error) {
    const message = error.message || 'Ошибка авторизации.';
    if (authOverlay) {
      authError.textContent = message;
    } else {
      formError.textContent = message;
    }
  }
}

async function deleteTask(taskId) {
  formError.textContent = '';
  try {
    await requestJson(`/api/tasks/${taskId}`, { method: 'DELETE' });
    await loadTasks();
  } catch (error) {
    formError.textContent = error.message || 'Ошибка при удалении задачи.';
  }
}

logoutButton.addEventListener('click', async () => {
  formError.textContent = '';
  try {
    await requestJson('/api/auth/logout', { method: 'POST' });
    setAuthenticatedUser(null);
  } catch (error) {
    formError.textContent = error.message || 'Ошибка выхода из аккаунта.';
  }
});

addTaskButton.addEventListener('click', async () => {
  formError.textContent = '';
  try {
    await requestJson('/api/tasks', {
      method: 'POST',
      body: JSON.stringify({
        title: titleInput.value.trim(),
        description: descriptionInput.value.trim()
      })
    });
    await loadTasks();
    titleInput.value = '';
    descriptionInput.value = '';
  } catch (error) {
    formError.textContent = error.message || 'Ошибка при отправке задачи.';
  }
});

async function initialize() {
  try {
    const { user } = await requestJson('/api/auth/me');
    setAuthenticatedUser(user);
    await loadTasks();
  } catch (error) {
    if (error.status === 401) {
      setAuthenticatedUser(null);
      return;
    }
    formError.textContent = error.message || 'Не удалось проверить сессию.';
  }
}

initialize();
