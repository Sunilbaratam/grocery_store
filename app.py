from flask import Flask, render_template, url_for, redirect, flash, request, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from datetime import datetime
from sqlalchemy import and_

app=Flask(__name__)
db=SQLAlchemy(app)
bcrypt=Bcrypt(app)
#C:\Users\barat\OneDrive\Desktop\abcd\instances\abc.db
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instances/abc.db'
app.config['SECRET_KEY']='thisisasecretkey'


login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_manager.user_loader
def load_admin(admin_id):
    return Admin.query.get(int(admin_id))


class User(db.Model, UserMixin):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(20), nullable=False, unique=True)
    password=db.Column(db.String(80), nullable=False)

class Admin(db.Model, UserMixin):
    admin_id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(20),unique=True,nullable=False)
    password=db.Column(db.String(80),nullable=False)

class Category(db.Model):
    category_id=db.Column(db.Integer,primary_key=True)
    category_name=db.Column(db.String(20),unique=True,nullable=False)

class Product(db.Model):
    product_id=db.Column(db.Integer,primary_key=True)
    product_name=db.Column(db.String(20),nullable=False)
    product_mdate=db.Column(db.Date,nullable=False)
    product_edate=db.Column(db.Date,nullable=False)
    product_cost=db.Column(db.Integer,nullable=False)
    product_stock=db.Column(db.Integer,nullable=False)
    category_id=db.Column(db.Integer,db.ForeignKey("category.category_id"),nullable=False)

class orders(db.Model):
    order_id=db.Column(db.Integer,primary_key=True)
    order_name=db.Column(db.String(20), nullable=False)
    order_value=db.Column(db.Integer,nullable=False)
    order_quantity=db.Column(db.Integer,nullable=False)
    order_total=db.Column(db.Integer,nullable=False)
    user_id=db.Column(db.String,db.ForeignKey("user.id"))



class RegisterForm(FlaskForm):
    username=StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder":"Username"})
    
    password=PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder":"Password"})
    
    submit=SubmitField("Register")

    def validate_username(self, username):
        existing_user_username=User.query.filter_by(
            username=username.data).first()
        
        if existing_user_username:
            raise ValidationError(
                "That username already exists. Pleas choose a differnt one.")


class LoginForm(FlaskForm):
    username=StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder":"Username"})
    password=PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder":"Password"})
    submit=SubmitField("Login")



@app.route('/')
def home():
    return render_template("index.html")

@app.route('/login', methods=['GET','POST'])
def login():
    form=LoginForm()

    if form.validate_on_submit():
        user=User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password,form.password.data):
                login_user(user, remember=True)
                return redirect(url_for('dashboard'))
            else:
                flash('Please type the right password', category='error')
        else:
            flash('No User, with that username', category='error')
    return render_template('login.html', form=form)


@app.route('/adminlogin',methods=['GET','POST'])
def adminlogin():
    form = LoginForm()
    if form.validate_on_submit():
        admin=Admin.query.filter_by(username=form.username.data).first()
        if admin:
            flash('enter the login')
            if bcrypt.check_password_hash(admin.password, form.password.data):
                login_user(admin, remember=True)
                return redirect(url_for('admindashboard'))
            else:
                flash('Please type the right password', category='error')
        else:
            flash('No User, with that username', category='error')
    return render_template('adminlogin.html', form=form)



@app.route('/dashboard', methods=["GET","POST"])
@login_required
def dashboard():
    all=Product.query.all()
    allc=Category.query.all()
    return render_template('dashboard.html',username=current_user.username, all=all, allc=allc)

@app.route('/admindashboard', methods=["GET","POST"])
@login_required
def admindashboard():
    return render_template('admindashboard.html')

@app.route('/adminlogout',methods=["GET","POST"])
@login_required
def adminlogout():
    logout_user()
    return redirect(url_for('adminlogin'))

@app.route('/logout',methods=["GET","POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/adminregister',methods=['GET','POST'])
def adminregister():
    form=RegisterForm()
    
    if form.validate_on_submit():
        hashed_password=bcrypt.generate_password_hash(form.password.data)
        new_admin=Admin(username=form.username.data, password=hashed_password)
        db.session.add(new_admin)
        db.session.commit()
        print(form)
        return redirect(url_for('adminlogin'))
    return render_template('adminregister.html', form=form)

@app.route('/registeradmin', methods=['GET','POST'])
def registeradmin():
    form=RegisterForm()
    if form.validate_on_submit():
        hashed_password=bcrypt.generate_password_hash(form.password.data)
        new_admin=Admin(username=form.username.data, password=hashed_password)
        db.session.add(new_admin)
        db.session.commit()
        return redirect(url_for('adminlogin'))
    return render_template('adminregister.html, form=form')

@app.route('/register', methods=['GET','POST'])
def register():
    form=RegisterForm()
    
    if form.validate_on_submit():
        hashed_password=bcrypt.generate_password_hash(form.password.data)
        new_user=User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html',form=form)


@app.route('/add/product',methods=['POST','GET'])
@login_required
def add_product():
    if request.method=='POST':
        product_name=request.form['p_name']
        product_mdate=datetime.strptime(request.form['p_mdate'], '%Y-%m-%d').date()
        product_edate=datetime.strptime(request.form['p_edate'], '%Y-%m-%d').date()
        product_cost=request.form['p_cost']
        product_stock=request.form['p_stock']
        category_id=request.form['c_id']
        product=Product(product_name=product_name,product_mdate=product_mdate,product_edate=product_edate,
                        product_cost=product_cost,product_stock=product_stock,category_id=category_id)
        db.session.add(product)
        db.session.commit()
        return redirect('/admindashboard')
    sun=Category.query.all()
    return render_template("ap.html",sun=sun)

@app.route('/add/category',methods=['POST','GET'])
@login_required
def add_category():
    if request.method=='POST':
        category_name=request.form['c_name']
        category=Category(category_name=category_name)
        db.session.add(category)
        db.session.commit()
        return redirect('/admindashboard')
    return render_template('ac.html')      

@app.route('/view/product') 
@login_required  
def view_product():
   
    sun=Product.query.all()
    
    return render_template("vp.html",sun=sun)

@app.route('/view/category')
@login_required
def view_category():
    sun=Category.query.all()
    return render_template("vc.html",sun=sun)


@app.route('/cat/update/<int:c_id>', methods = ['POST','GET'])
def cat_update(c_id):
    if request.method == 'POST':
        cat=Category.query.get(c_id)
        cat.category_name = request.form['c1_name']
        db.session.commit()
        return redirect('/view/category')
    d=Category.query.get(c_id)
    return render_template("ec.html",d=d)

@app.route('/prod/update/<int:p_id>', methods = ['POST','GET'])
def prod_update(p_id):
    if request.method == 'POST':
        prod=Product.query.get(p_id)
        prod.p_name = request.form['p1_name']
        prod.p_mdate=datetime.strptime(request.form['p1_mdate'], '%Y-%m-%d').date()
        prod.p_edate=datetime.strptime(request.form['p1_edate'], '%Y-%m-%d').date()
        prod.p_cost=request.form['p1_cost']
        prod.p_stock=request.form['p1_stock']
        db.session.commit()
        return redirect('/view/product')
    drop=Product.query.get(p_id)
    return render_template("ep.html",drop=drop)

@app.route('/prod/delete/<int:id>')
def deleteproduct(id):
    prod=Product.query.get(id)
    db.session.delete(prod)
    db.session.commit()
    return redirect('/view/product')

@app.route('/cat/delete/<int:id>')
def deletecategory(id):
    cat=Category.query.get(id)
    prod=Product.query.filter(Product.category_id==cat.category_id).all()
    for i in range(len(prod)):
        db.session.delete(prod[i])
    db.session.delete(cat)
    db.session.commit()
    return redirect('/view/category')

@app.route('/category/product/<string:name>')
def get_products(name):
    nameid=Category.query.filter(Category.c_name==name).with_entities(Category.c_name).all()
    res=Product.query.filter(Product.c_id==nameid[0][0]).all()
    
    return render_template("ucp.html",nameid=nameid,res=res)

@app.route('/ordering',methods=['POST','GET'])
def ordering():
    if request.method == 'POST':
        pro_id=request.form['product_id']
        quantity=int(request.form['product_quant'])
        pro=Product.query.get(pro_id)
        print(pro)
        pro_details={
            'pname':pro.product_name,
            'cost':pro.product_cost,
            'quantity':quantity,
            'total_price':pro.product_cost*quantity
        }
            

        
        if 'cart' not in session:
            session['cart']=[]
        session['cart'].append(pro_details)
        n_quant=session['cart'][-1]['quantity']
        print(n_quant)
        print(type(n_quant))
        print("hai")
        name=session['cart'][-1]['pname']
        x=Product.query.filter(Product.product_name==session['cart'][-1]['pname']).all()
        o_quant=x[0].product_stock
        if o_quant>0 and n_quant<o_quant :
            update_quant=o_quant-n_quant
            print(o_quant)
            print(n_quant)
            print(update_quant)
            x[0].p_stock=update_quant
            db.session.commit()
            session.modified=True
        elif o_quant>0 and n_quant>o_quant:
            render_template('blank.html')
        else:
            x[0].p_stock=0
            db.session.commit()
        session.modified=True
    print(session['cart'])
    return redirect('/dashboard')



@app.route('/mycart',methods=['GET','POST'])
def view_cart():
    if 'cart' in session:
        cart=session['cart']
        total_amount=sum(item['total_price'] for item in cart)
    else:
        cart=[]
        total_amount=0
    return render_template('sbag.html',cart=cart,total_amount=total_amount)

@app.route('/receipt')
def receipt():
    if 'cart' in session:
        for i in range(len(session['cart'])):
            #username=session['username']
            pname=session['cart'][i]['pname']
            cost=session['cart'][i]['cost']
            quantity=session['cart'][i]['quantity']
            total_price=session['cart'][i]['total_price']
            order=orders(user_id=session['_user_id'],order_name=pname,order_value=cost,order_quantity=quantity,order_total=total_price)
            db.session.add(order)
            db.session.commit()    
        cart=session['cart']
        total_amount=sum(item['total_price'] for item in cart)
    else:
        cart=[]
        total_amount=0
    return render_template("reciept.html")


@app.route('/ordersf')
def ordersf():
    sun=orders.query.filter(orders.user_id==session['_user_id']).all()
    if(len(sun)==0):
        return "error"
    #print(all[1])
    return render_template('orders.html',sun=sun)

@app.route('/search/<int:k>')
def search(k):
    if(k==1):
        
        z=Product.query.filter(and_(Product.p_cost > 0, Product.p_cost <= 20))
        return render_template("search.html",z=z)
    elif(k==2):
        
        z=Product.query.filter(and_(Product.p_cost > 20, Product.p_cost <= 40))
        return render_template("search.html",z=z)   
    elif(k==3):
        
        z=Product.query.filter(and_(Product.p_cost >40, Product.p_cost <= 100))
        return render_template("search.html",z=z)   
    elif(k==4):
        x=Product.query.filter(Product.p_cost >100)
        return render_template("search.html",z=z)
        
    return render_template('search.html')
if __name__== '__main__':
    app.run(debug=True)

